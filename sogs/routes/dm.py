from .. import db, http, utils
from ..model.exc import NoSuchUser
from ..model.user import User
from ..model.message import Message
from ..web import app
from . import auth

from flask import abort, jsonify, g, Blueprint, request, Response

dm = Blueprint('dm', __name__)


def _serialize_message(msg, include_message=True):
    m = {
        "id": msg.id,
        "posted_at": msg.posted_at,
        "expires_at": msg.expires_at,
        "sender": msg.signing_key,
        "recipient": msg.recipient.session_id,
    }
    if include_message:
        m["message"] = utils.encode_base64(msg.data)
    return m


def _box(out: bool, *, since=None):
    """handle inbox/outbox endpoints common logic"""
    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)
    get = Message.sent if out else Message.to
    msgs = [_serialize_message(msg) for msg in get(user=g.user, limit=limit, since=since)]
    if msgs or since is None:
        return jsonify(msgs)
    return Response('', status=http.NOT_MODIFIED)


@dm.get("/outbox")
@auth.blind_user_required
def get_outbox():
    """
    Retrieves all of the user's sent messages (up to `limit`).
    """
    return _box(True)


@dm.get("/outbox/since/<int:msgid>")
@auth.blind_user_required
def poll_outbox(msgid):
    """
    Polls for any DMs sent since the given id.
    """
    return _box(True, since=msgid)


@dm.get("/inbox")
@auth.blind_user_required
def get_inbox():
    """
    Retrieves all of the user's recieved messages (up to `limit`).
    """
    return _box(False)


@dm.get("/inbox/since/<int:msgid>")
@auth.blind_user_required
def poll_inbox(msgid):
    """
    Polls for any DMs received since the given id.
    """
    return _box(False, since=msgid)


@dm.post("/inbox/<BlindSessionID:sid>")
@auth.user_required
def send_inbox(sid):
    """
    Delivers a direct message to a user via their blinded Session ID.

    The body of this request is a JSON object containing a `message` key with a value of the
    encrypted-then-base64-encoded message to deliver.

    Message encryption is described in the [`GET` /inbox](#GET-inbox) endpoint.

    # Return value

    On successful deposit of the message a 201 (Created) status code is returned.  The body will be
    a JSON object containing the message details as would be returned by retrieving the message,
    except that it omits the encrypted message body.

    # Error status codes

    400 Bad Request — if no message is provided.

    404 Not Found — if the given Session ID does not exist on this server, either because they have
    never accessed the server, or because they have been permanently banned.
    """
    print(f"inbox post, recipient = {sid}")
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
        alt_id = g.user.using_id if g.user.using_id != g.user.session_id else None
        msg = Message(
            data=utils.decode_base64(message), recip=recip_user, sender=g.user, alt_id=alt_id
        )
    return jsonify(_serialize_message(msg, include_message=False)), http.CREATED


@dm.delete("/inbox")
@auth.blind_user_required
def delete_inbox_items():
    """
    Deletes all of the user's received messages.

    # Return value

    Returns a JSON object with one key `"deleted"` set to the number of deleted messages.
    """
    ret = dict()
    with db.transaction():
        ret['deleted'] = Message.delete_all(recip=g.user)

    return jsonify(ret), http.OK
