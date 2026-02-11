from flask import abort, request, jsonify, g, Blueprint, Response
from werkzeug.exceptions import HTTPException
from ..web import app
from .. import crypto, config, db, http, utils
from ..omq import send_mule
from ..utils import jsonify_with_base64
from ..model.room import Room, get_accessible_rooms, get_deletions_deprecated
from ..model.user import User
from ..model.exc import NoSuchRoom

# Legacy endpoints, to eventually be deleted.  These are invoked automatically if the client invokes
# an endpoint (via onion request) that doesn't start with a `/` -- we prepend `/legacy/` and submit
# it as an internal request to land here.

legacy = Blueprint('legacy', __name__, url_prefix='/legacy')


def get_pubkey_from_token(token):
    if not token:
        return
    try:
        rawtoken = utils.decode_hex_or_b64(token, utils.LEGACY_TOKEN_SIZE)
        crypto.server_verify(rawtoken)
    except Exception as ex:
        app.logger.error("failed to decode/verify token: {}".format(ex))
        abort(http.UNAUTHORIZED)
    else:
        return rawtoken[utils.SIGNATURE_SIZE :].hex()


def legacy_check_user_room(
    pubkey=None, room_token=None, *, room=None, update_activity=True, no_perms=False, **perms
):
    """
    For a legacy endpoint verifying a user is allowed to access a room calls flask.abort to bail out
    if the user is not allowed, otherwise returns a pair: the user and room info.

    pubkey - the session_id of the user.  If None we verify and extract it from the current
    request's X-SOGS-* headers (if present) or Authorization header.

    room_token - the token of the room.  If None we verify and extract it from the current request's
    Room header.

    room - the Room itself, if already retrieved (e.g. from a URL parameter).  If non-None then
    `room_token` is ignored entirely.

    update_activity - if True (the default) then update the user's overall last activity and last
    room activity counters.

    no_perms - if True then do not do any permission check at all; this should only be used when the
    permission check needs to be done externally e.g. for complex permission validation.  When this
    is specified any extra keyword arguments (which would be passed to check_permissions) are
    ignored.

    Any other arguments are passed to Room.check_permission (e.g. `read=True`).  We enforce here
    that you pass at least one such permission (unless using `no_perms`); if you really need
    all-false (e.g. to only do ban check) then pass `read=False`.
    """

    if len(perms) == 0 and not no_perms:
        raise ValueError("Internal error: no permissions passed to legacy_check_user_room")

    if pubkey is None:
        if 'user' in g and g.user:
            pubkey = g.user.using_id
        else:
            pubkey = get_pubkey_from_token(request.headers.get("Authorization"))
    if not pubkey or len(pubkey) != (utils.SESSION_ID_SIZE * 2) or not pubkey.startswith('05'):
        app.logger.warning("cannot get pubkey for checking room permissions")
        abort(http.BAD_REQUEST)
    if config.REQUIRE_BLIND_KEYS and pubkey.startswith('05'):
        msg = "Invalid authentication: this server requires the use of blinded ids"
        app.logger.warning(msg)
        abort(Response(msg, status=http.BAD_REQUEST, mimetype='text/plain'))

    if room is None:
        if room_token is None:
            room_token = request.headers.get("Room")
        if not room_token:
            abort(http.BAD_REQUEST)

        try:
            room = Room(token=room_token)
        except NoSuchRoom:
            abort(http.NOT_FOUND)

    user = User(session_id=pubkey, autovivify=True, touch=update_activity)

    if not no_perms:
        if not room.check_permission(user, **perms):
            abort(http.FORBIDDEN)

    if update_activity:
        user.update_room_activity(room)

    return (user, room)


@legacy.get("/rooms")
def get_rooms():
    # serve public room list for user

    return jsonify(
        {
            'status_code': http.OK,
            # Legacy Session only wants token (returned as 'id') and name:
            'rooms': [{'id': r.token, 'name': r.name} for r in get_accessible_rooms()],
        }
    )


@legacy.get("/rooms/<Room:room>")
def get_room_info(room):
    # serve room metadata

    # This really should be authenticated but legacy Session just doesn't pass along auth info.
    # legacy_check_user_room(room=room, update_activity=False, accessible=True)

    # NB: this endpoint leaks the room name even when a room is inaccessible as a result because
    # there is *no* way to know who is requesting the room name.

    room_info = {'id': room.token, 'name': room.name}
    return jsonify({'room': room_info, 'status_code': http.OK})


@legacy.get("/rooms/<Room:room>/image")
def legacy_serve_room_image(room):
    # serve room icon

    # This really should be authenticated but legacy Session just doesn't pass along auth info.
    # legacy_check_user_room(room=room, update_activity=False, accessible=True)

    # NB: this endpoint leaks the room image even when a room is inaccessible as a result because
    # there is *no* way to know who is requesting the room image.

    if not room.image:
        abort(http.NOT_FOUND)

    return jsonify({"status_code": http.OK, "result": room.image.read_base64()})


@legacy.get("/member_count")
def legacy_member_count():
    user, room = legacy_check_user_room(accessible=True)

    return jsonify({"status_code": http.OK, "member_count": room.active_users})


@legacy.post("/claim_auth_token")
def legacy_claim_auth():
    # this does nothing but needs to exist for backwards compat

    return jsonify({'status_code': http.OK})


@legacy.get("/auth_token_challenge")
def legacy_auth_token_challenge():
    # legacy endpoint to give back an encrypted auth token bundle for the client to use to
    # authenticate.

    user, room = legacy_check_user_room(request.args.get("public_key", ""), read=False)

    token = utils.make_legacy_token(user.session_id)
    pk = utils.decode_hex_or_b64(user.session_id[2:], 32)
    return jsonify_with_base64(
        {
            'status_code': http.OK,
            'challenge': {
                'ciphertext': crypto.server_encrypt(pk, token),
                'ephemeral_public_key': crypto.server_pubkey_base64,
            },
        }
    )


def legacy_transform_message(m):
    """Transform new API fields into legacy Session fields"""
    return {
        'server_id': m['id'],
        'public_key': m['session_id'],
        'timestamp': utils.legacy_convert_time(m['posted']),
        'data': m['data'],
        'signature': m['signature'],
    }


@legacy.post("/messages")
def handle_post_legacy_message():
    user, room = legacy_check_user_room(write=True)

    req = request.json
    data = utils.decode_base64(req.get('data'))
    sig = utils.decode_base64(req.get('signature'))

    return jsonify_with_base64(
        {
            'status_code': http.OK,
            'message': legacy_transform_message(room.add_post(user, data, sig)),
        }
    )


@legacy.get("/messages")
def handle_legacy_get_messages():
    from_id = request.args.get('from_server_id')
    limit = utils.get_int_param('limit', 256, min=1, max=256, truncate=True)

    user, room = legacy_check_user_room(read=True)

    return jsonify_with_base64(
        {
            'status_code': http.OK,
            'messages': [
                legacy_transform_message(m)
                for m in room.get_messages_for(user, limit=limit, after=from_id, recent=not from_id)
            ],
        }
    )


@legacy.post("/compact_poll")
def handle_comapct_poll():
    req_list = request.json
    result = list()
    for req in req_list.get('requests', list()):
        try:
            r = handle_one_compact_poll(req)
        except HTTPException as e:
            # Hack for Session: if there isn't a full fleshed out response then Session just ignores
            # the response (even when it's an error response), so we send this fake response:
            r = {
                'status_code': e.get_response().status_code,
                'room_id': req.get('room_id', ''),
                'messages': [],
                'deletions': [],
                'moderators': [],
            }
        result.append(r)

    return jsonify_with_base64({'status_code': http.OK, 'results': result})


def handle_one_compact_poll(req):
    user, room = legacy_check_user_room(
        get_pubkey_from_token(req.get('auth_token')) or '', req.get('room_id', ''), read=True
    )

    after = req.get('from_message_server_id', None)
    messages = [
        legacy_transform_message(m)
        for m in room.get_messages_for(user, after=after, recent=not after)
    ]

    deletions = get_deletions_deprecated(room, req.get('from_deletion_server_id'))

    mods = sorted(session_id for moderators in room.get_mods(user) for session_id in moderators)

    return {
        'status_code': http.OK,
        'room_id': room.token,
        'messages': messages,
        'deletions': deletions,
        'moderators': mods,
    }


def process_legacy_file_upload_for_room(user, room, lifetime=config.UPLOAD_DEFAULT_EXPIRY):
    """
    Uploads a file, posted by user, into the given room.  `lifetime` controls how long (in seconds)
    the file will be stored before expiry, and can be None for uploads (such as room images) that
    shouldn't expire.
    """

    # Slamming this all into memory is not very nice, but there's no terribly elegant way to get
    # around it when we have b64 input for legacy uploads.
    file_b64 = request.json['file']
    file_content = utils.decode_base64(file_b64)

    if len(file_content) > config.UPLOAD_FILE_MAX_SIZE:
        abort(http.PAYLOAD_TOO_LARGE)

    filename = None  # legacy Session doesn't provide a filename, just a random blob
    return room.upload_file(file_content, user, filename=filename, lifetime=lifetime)


@legacy.post("/files")
def handle_legacy_store_file():
    user, room = legacy_check_user_room(write=True, upload=True)
    file_id = process_legacy_file_upload_for_room(user, room)
    return jsonify({'status_code': http.OK, 'result': file_id})


@legacy.post("/rooms/<Room:room>/image")
def handle_legacy_upload_room_image(room):
    user, room = legacy_check_user_room(admin=True)
    file_id = process_legacy_file_upload_for_room(user, room, lifetime=None)
    room.image = file_id
    return jsonify({'status_code': http.OK, 'result': file_id})


@legacy.get("/files/<int:file_id>")
def handle_legacy_get_file(file_id):
    user, room = legacy_check_user_room(read=True)

    file = room.get_file(file_id)
    if not file:
        abort(http.NOT_FOUND)

    with open(file.path, 'rb') as f:
        file_content = f.read()
    return jsonify_with_base64({'status_code': http.OK, 'result': file_content})


@legacy.post("/delete_messages")
def handle_legacy_delete_messages(ids=None):
    user, room = legacy_check_user_room(read=True)

    if ids is None:
        ids = request.json['ids']

    ids = room.delete_posts(ids, user)

    if ids:
        send_mule("messages_deleted", ids)

    return jsonify({'status_code': http.OK})


@legacy.delete("/messages/<int:msgid>")
def handle_legacy_single_delete(msgid):
    return handle_legacy_delete_messages(ids=[msgid])


@legacy.post("/block_list")
def handle_legacy_ban():
    user, room = legacy_check_user_room(moderator=True)
    ban = User(session_id=request.json['public_key'], autovivify=True)

    room.ban_user(to_ban=ban, mod=user)

    return jsonify({"status_code": http.OK})


@legacy.post("/ban_and_delete_all")
def handle_legacy_banhammer():
    mod, room = legacy_check_user_room(moderator=True)
    ban = User(session_id=request.json['public_key'], autovivify=True)

    with db.transaction():
        room.ban_user(to_ban=ban, mod=mod)
        room.delete_all_posts(ban, deleter=mod)

    return jsonify({"status_code": http.OK})


@legacy.delete("/block_list/<SessionID:session_id>")
def handle_legacy_unban(session_id):
    user, room = legacy_check_user_room(moderator=True)
    to_unban = User(session_id=session_id, autovivify=False)
    if room.unban_user(to_unban, mod=user):
        return jsonify({"status_code": http.OK})

    abort(http.NOT_FOUND)


@legacy.get("/block_list")
def handle_legacy_banlist():
    # Bypass permission checks here because we want to continue even if we are banned:
    user, room = legacy_check_user_room(no_perms=True)

    # If you are a moderator then we show you everything; if you are banned we show you just
    # yourself; otherwise we show you nothing.
    if not room.check_unbanned(user):
        bans = [user.session_id]
    elif room.check_moderator(user):
        bans = room.get_bans()
    else:
        bans = []

    return jsonify({"status_code": http.OK, "banned_members": bans})


@legacy.get("/moderators")
def handle_legacy_get_mods():
    user, room = legacy_check_user_room(read=True)

    mods = sorted(session_id for moderators in room.get_mods(user) for session_id in moderators)
    return jsonify({"status_code": http.OK, "moderators": mods})


# Posting here adds an admin and requires admin access.  Legacy Session doesn't understand the
# moderator/admin distinction so we don't support moderator adjustment at all here.
@legacy.post("/moderators")
def handle_legacy_add_admin():
    user, room = legacy_check_user_room(admin=True)

    session_id = request.json["public_key"]
    if len(session_id) != 66 or not session_id.startswith("05"):
        abort(http.BAD_REQUEST)

    mod = User(session_id=session_id, autovivify=True)
    room.set_moderator(mod, admin=True, visible=True, added_by=user)

    return jsonify({"status_code": http.OK})


# DELETE here removes an admin or moderator and requires admin access.  (Legacy Session doesn't
# understand the moderator/admin distinction so we don't distinguish between them and just remove
# both powers, if present).
@legacy.delete("/moderators/<SessionID:session_id>")
def handle_legacy_remove_admin(session_id):
    user, room = legacy_check_user_room(admin=True)

    mod = User(session_id=session_id, autovivify=False)
    room.remove_moderator(mod, removed_by=user)

    return jsonify({"status_code": http.OK})
