from .. import db, http, utils
from ..model import room as mroom
from ..model.exc import NoSuchUser
from ..model.user import User
from ..model.message import Message
from ..web import app
from . import auth

from flask import abort, jsonify, g, Blueprint, request, Response

# User-related routes


users = Blueprint('users', __name__)


def extract_rooms_or_global(req, admin=True):
    """
    Extracts the rooms / global parameters from the request body checking them for validity and
    expanding them as appropriate.

    Throws a flask abort on failure, returns (rooms, global) which will be either ([list of Rooms],
    None) for a room operation or (None, True) for a global operation.

    admin specifies whether we require admin permission (if True) or just moderator permission,
    either in all rooms specified, or globally.  (Similarly it affects what `rooms=['*']` expands
    to).
    """

    if not isinstance(req, dict):
        app.logger.warning(f"Invalid request: expected a JSON object body, not {type(req)}")
        abort(http.BAD_REQUEST)

    room_tokens, global_ = req.get('rooms'), req.get('global', False)

    if room_tokens and not isinstance(room_tokens, list):
        app.logger.warning("Invalid request: rooms must be a list")
        abort(http.BAD_REQUEST)

    if room_tokens and global_:
        app.logger.warning("Invalid moderator request: cannot specify both 'rooms' and 'global'")
        abort(http.BAD_REQUEST)

    if not room_tokens and not global_:
        app.logger.warning("Invalid moderator request: neither 'rooms' nor 'global' specified")
        abort(http.BAD_REQUEST)

    if room_tokens:
        if len(room_tokens) > 1 and '*' in room_tokens:
            app.logger.warning("Invalid moderator request: room '*' must be the only rooms value")
            abort(http.BAD_REQUEST)

        if room_tokens == ['*']:
            room_tokens = None

        try:
            rooms = mroom.get_rooms_with_permission(
                g.user, tokens=room_tokens, moderator=True, admin=True if admin else None
            )
        except Exception as e:
            # This is almost certainly a bad room token passed in:
            app.logger.warning(f"Cannot get rooms for adding a moderator: {e}")
            abort(http.NOT_FOUND)

        if room_tokens:
            if len(rooms) != len(room_tokens):
                abort(http.FORBIDDEN)
        elif not rooms:
            abort(http.FORBIDDEN)

        return (rooms, None)

    if not g.user.global_moderator or (admin and not g.user.global_admin):
        abort(http.FORBIDDEN)

    return (None, True)


def _serialize_message(msg):
    return {
        "id": msg.id,
        "posted_at": msg.posted_at,
        "expires_at": msg.expires_at,
        "message": utils.encode_base64(msg.data),
        "sender": msg.sender.session_id,
    }


@users.get("/inbox")
@auth.user_required
def get_inbox():
    """gets all messages"""
    if not g.user.is_blinded:
        abort(http.FORBIDDEN)
    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)
    return jsonify([_serialize_message(msg) for msg in Message.to(user=g.user, limit=limit)])


@users.get("/inbox/since/<int:msgid>")
@auth.user_required
def poll_inbox(msgid):
    """Returns DMs received since the given id"""
    if not g.user.is_blinded:
        abort(http.FORBIDDEN)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)
    msgs = [_serialize_message(msg) for msg in Message.to(user=g.user, since=msgid, limit=limit)]
    if len(msgs) > 0:
        return jsonify(msgs)
    return Response('', status=http.NOT_MODIFIED)


@users.post("/inbox/<BlindSessionID:sid>")
@auth.user_required
def send_inbox(sid):
    """send a message to a recipient user via their session id"""
    try:
        recip_user = User(session_id=sid, autovivify=False)
    except NoSuchUser:
        abort(http.NOT_FOUND)

    if recip_user.banned:
        abort(http.NOT_FOUND)

    req = request.json
    message = req.get('message')
    if message is None:
        app.logger.warning("No message provided")
        abort(http.BAD_REQUEST)

    with db.transaction():
        msg = Message(data=utils.decode_base64(message), recip=recip_user, sender=g.user)
    return jsonify({"expires_at": msg.expires_at}), http.CREATED


@users.post("/user/<SessionID:sid>/moderator")
@auth.user_required
def set_mod(sid):

    user = User(session_id=sid)

    req = request.json

    rooms, global_mod = extract_rooms_or_global(req)

    mod, admin, visible = (
        None if arg is None else bool(arg)
        for arg in (req.get('moderator'), req.get('admin'), req.get('visible'))
    )

    # Filter out any invalid or redundant arguments:
    if (admin, mod) == (None, None):
        app.logger.warning(
            "Invalid moderator request: at least one of admin/moderator must be specified"
        )
        abort(http.BAD_REQUEST)
    elif (admin, mod) == (True, False):
        app.logger.warning("Invalid moderator call: admin=True, moderator=False is impossible")
        abort(http.BAD_REQUEST)
    elif (admin, mod) == (True, True):
        mod = None  # admin already implies mod so we can ignore it
    elif (admin, mod) == (False, False):
        admin = None  # ¬mod implies ¬admin so we can ignore it

    # We now have one of these cases:
    # (True, None) -- adds admin
    # (None, True) -- adds mod
    # (None, False) -- removes mod/admin
    # (False, True) -- removes admin, adds mod
    # (False, None) -- removes admin

    if rooms:
        if visible is None:
            visible = True

        with db.transaction():
            for room in rooms:
                if (admin, mod) in ((True, None), (None, True)):
                    room.set_moderator(user, added_by=g.user, admin=admin, visible=visible)
                elif (admin, mod) == (None, False):
                    room.remove_moderator(user, removed_by=g.user)
                elif (admin, mod) == (False, None):
                    room.remove_moderator(user, removed_by=g.user, remove_admin_only=True)
                elif (admin, mod) == (False, True):
                    room.remove_moderator(user, removed_by=g.user, remove_admin_only=True)
                    room.set_moderator(user, added_by=g.user, admin=False, visible=visible)
                else:
                    app.logger.error("Internal error: unhandled mod/admin room case")
                    raise RuntimeError("Internal error: unhandled mod/admin room case")

    else:  # global mod
        if visible is None:
            visible = False

        if (admin, mod) in ((True, None), (None, True)):
            user.set_moderator(added_by=g.user, admin=admin, visible=visible)
        elif (admin, mod) == (None, False):
            user.remove_moderator(removed_by=g.user)
        elif (admin, mod) == (False, None):
            user.remove_moderator(removed_by=g.user, remove_admin_only=True)
        elif (admin, mod) == (False, True):
            with db.transaction():
                user.remove_moderator(removed_by=g.user, remove_admin_only=True)
                user.set_moderator(added_by=g.user, admin=bool(admin), visible=visible)

    return jsonify({})


@users.post("/user/<SessionID:sid>/ban")
@auth.user_required
def ban_user(sid):

    user = User(session_id=sid)
    req = request.json
    rooms, global_ban = extract_rooms_or_global(req, admin=False)

    timeout = req.get('timeout')
    if timeout is not None and not isinstance(timeout, int) and not isinstance(timeout, float):
        app.logger.warning("Invalid ban request: timeout must be numeric")
        abort(http.BAD_REQUEST)

    if rooms:
        with db.transaction():
            for room in rooms:
                room.ban_user(to_ban=user, mod=g.user, timeout=timeout)
    else:
        user.ban(banned_by=g.user, timeout=timeout)

    return {}


@users.post("/user/<SessionID:sid>/unban")
@auth.user_required
def unban_user(sid):

    user = User(session_id=sid)
    rooms, global_ban = extract_rooms_or_global(request.json, admin=False)

    if rooms:
        with db.transaction():
            for room in rooms:
                room.unban_user(to_unban=user, mod=g.user)
    else:
        user.unban(unbanned_by=g.user)

    return {}
