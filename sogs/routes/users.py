from .. import db, http
from ..model import room as mroom
from ..model.user import User
from ..web import app
from . import auth

from flask import abort, jsonify, g, Blueprint, request

# User-related routes


users = Blueprint('users', __name__)


@users.post("/user/<SessionID:sid>/moderator")
@auth.user_required
def set_mod(sid):

    user = User(session_id=sid)

    req = request.json
    room_tokens, global_mod = req.get('rooms'), req.get('global', False)

    if room_tokens and not isinstance(room_tokens, list):
        app.logger.warning("Invalid request: room_tokens must be a list")
        abort(http.BAD_REQUEST)

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

    with db.transaction():
        if room_tokens:
            if visible is None:
                visible = True

            if global_mod:
                app.logger.warning(
                    "Invalid moderator request: cannot specify both 'rooms' and 'global'"
                )
                abort(http.BAD_REQUEST)

            if len(room_tokens) > 1 and '*' in room_tokens:
                app.logger.warning(
                    "Invalid moderator request: room '*' must be the only rooms value"
                )
                abort(http.BAD_REQUEST)

            if room_tokens == ['*']:
                room_tokens = None

            try:
                rooms = mroom.get_rooms_with_permission(g.user, tokens=room_tokens, admin=True)
            except Exception as e:
                # This is almost certainly a bad room token passed in:
                app.logger.warning(f"Cannot get rooms for adding a moderator: {e}")
                abort(http.BAD_REQUEST)

            if room_tokens is not None:
                if len(rooms) != len(room_tokens):
                    abort(http.FORBIDDEN)
            elif not rooms:
                abort(http.FORBIDDEN)

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
                user.remove_moderator(removed_by=g.user, remove_admin_only=True)
                user.set_moderator(added_by=g.user, admin=bool(admin), visible=visible)

    return jsonify({})
