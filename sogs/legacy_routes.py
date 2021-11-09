from flask import abort, request, jsonify, send_file
from .web import app
from . import crypto
from . import model
from . import db
from . import utils
from . import config
from . import http

import os
import time
import re

# Legacy endpoints, to eventually be deleted.  These are invoked automatically if the client invokes
# an endpoint (via onion request) that doesn't start with a `/` -- we prepend `/legacy/` and submit
# it as an internal request to land here.


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
    request's Authorization header.

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

    Any other arguments are passed to model.check_permission (e.g. `read=True`).  We enforce here
    that you pass at least one such permission (unless using `no_perms`); if you really need
    all-false (e.g. to only do ban check) then pass `read=False`.
    """

    if len(perms) == 0 and not no_perms:
        raise ValueError("Internal error: no permissions passed to legacy_check_user_room")

    if pubkey is None:
        pubkey = get_pubkey_from_token(request.headers.get("Authorization"))
    if not pubkey or len(pubkey) != (utils.SESSION_ID_SIZE * 2) or not pubkey.startswith('05'):
        app.logger.warn("cannot get pubkey for checking room permissions")
        abort(http.BAD_REQUEST)

    if room is None:
        if room_token is None:
            room_token = request.headers.get("Room")
        if not room_token:
            abort(http.BAD_REQUEST)

        try:
            room = model.Room(token=room_token)
        except model.NoSuchRoom:
            abort(http.NOT_FOUND)

    user = model.User(session_id=pubkey, autovivify=True, touch=update_activity)

    if not no_perms:
        if not model.check_permission(user, room, **perms):
            abort(http.FORBIDDEN)

    if update_activity:
        with db.conn as conn:
            conn.execute(
                """
                INSERT INTO room_users (user, room) VALUES (?, ?)
                ON CONFLICT(user, room) DO UPDATE SET last_active = ((julianday('now') - 2440587.5)*86400.0)
                """,
                (user.id, room.id),
            )

    return (user, room)


@app.get("/legacy/rooms")
def get_rooms():
    """serve room list for user"""
    pubkey = get_pubkey_from_token(request.headers.get("Authorization"))
    if not pubkey:
        abort(http.BAD_REQUEST)

    return jsonify(
        {
            'status_code': 200,
            # Legacy Session only wants token (returned as 'id') and name:
            rooms: [{'id': r.token, 'name': r.name} for r in model.get_readable_rooms(pubkey)],
        }
    )


@app.get("/legacy/rooms/<Room:room>")
def get_room_info(room):
    """serve room metadata"""
    # This really should be authenticated but legacy Session just doesn't pass along auth info.
    # legacy_check_user_room(room=room, update_activity=False, read=True)
    room_info = {'id': room.token, 'name': room.name}
    return jsonify({'room': room_info, 'status_code': 200})


@app.get("/legacy/rooms/<Room:room>/image")
def legacy_serve_room_image(room):
    """serve room icon"""
    # This really should be authenticated but legacy Session just doesn't pass along auth info.
    # legacy_check_user_room(room=room, update_activity=False, read=True)

    if not room.image:
        abort(http.NOT_FOUND)

    return jsonify({"status_code": 200, "result": room.image.read_base64()})


@app.get("/legacy/member_count")
def legacy_member_count():
    user, room = legacy_check_user_room(read=True)

    return jsonify({"status_code": 200, "member_count": room.active_users()})


@app.post("/legacy/claim_auth_token")
def legacy_claim_auth():
    """this does nothing but needs to exist for backwards compat"""
    return jsonify({'status_code': 200})


@app.get("/legacy/auth_token_challenge")
def legacy_auth_token_challenge():
    """
    legacy endpoint to give back an encrypted auth token bundle for the client to use to
    authenticate.
    """

    user, room = legacy_check_user_room(request.args.get("public_key", ""), read=False)

    token = utils.make_legacy_token(user.session_id)
    pk = utils.decode_hex_or_b64(user.session_id[2:], 32)
    ct = crypto.server_encrypt(pk, token)
    return jsonify(
        {
            'status_code': 200,
            'challenge': {
                'ciphertext': utils.encode_base64(ct),
                'ephemeral_public_key': crypto.server_pubkey_base64,
            },
        }
    )


@app.post("/legacy/messages")
def handle_post_legacy_message():

    user, room = legacy_check_user_room(write=True)

    req = request.json
    data = utils.decode_base64(req.get('data'))
    sig = utils.decode_base64(req.get('signature'))
    msg = model.add_post_to_room(user.id, room.id, data, sig)
    if not msg:
        abort(http.TOO_MANY_REQUESTS)
    msg['public_key'] = user.session_id
    msg['data'] = req.get('data')
    msg['signature'] = req.get('signature')
    return jsonify({'status_code': 200, 'message': msg})


@app.get("/legacy/messages")
def handle_legacy_get_messages():
    from_id = request.args.get('from_server_id')
    limit = utils.get_int_param('limit', 256, min=1, max=256, truncate=True)

    user, room = legacy_check_user_room(read=True)

    return jsonify(
        {'status_code': 200, 'messages': model.get_message_deprecated(room.id, from_id, limit)}
    )


@app.post("/legacy/compact_poll")
def handle_comapct_poll():
    req_list = request.json
    result = list()
    for req in req_list.get('requests', list()):
        result.append(handle_one_compact_poll(req))
    return jsonify({'status_code': 200, 'results': result})


def handle_one_compact_poll(req):
    user, room = legacy_check_user_room(
        get_pubkey_from_token(req.get('auth_token')) or '', req.get('room_id', ''), read=True
    )

    messages = model.get_message_deprecated(room.id, req.get('from_message_server_id'))

    deletions = model.get_deletions_deprecated(room.id, req.get('from_deletion_server_id'))

    mods = room.get_mods(user)

    return {
        'status_code': 200,
        'room_id': room.token,
        'messages': messages,
        'deletions': deletions,
        'moderators': mods,
    }


def process_legacy_file_upload_for_room(
    user, room, lifetime=config.UPLOAD_DEFAULT_EXPIRY_DAYS * 86400
):
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
        abort(http.ERROR_PAYLOAD_TOO_LARGE)

    files_dir = "uploads/" + room.token
    os.makedirs(files_dir, exist_ok=True)

    # FIXME: when making this code generic, filename should be provided by new API users
    filename = None

    if filename is not None:
        filename = re.sub(config.UPLOAD_FILENAME_BAD, "_", filename)

    file_id, file_path = None, None

    try:
        # Begin a transaction; if this context exits with exception we want to roll back the
        # database addition; we catch *outside* the context so that we catch on commit, as well, so
        # that we also clean up the stored file on disk if the transaction fails to commit.
        with db.conn:
            expiry = None if lifetime is None else time.time() + lifetime

            # Insert the file row first, but with nonsense path because we want to put the ID in the
            # path, which we won't have until after the insert; we'll come back and update it.
            cur = db.conn.cursor()
            cur.execute(
                """
                INSERT INTO files (room, uploader, size, expiry, filename, path)
                VALUES (?, ?, ?, ?, ?, 'tmp')
                """,
                (room.id, user.id, len(file_content), expiry, filename),
            )

            file_id = cur.lastrowid

            if filename is None:
                filename = '(unnamed)'

            if len(filename) > config.UPLOAD_FILENAME_MAX:
                filename = (
                    filename[: config.UPLOAD_FILENAME_KEEP_PREFIX]
                    + "..."
                    + filename[-config.UPLOAD_FILENAME_KEEP_SUFFIX :]
                )

            file_path = "{}/{}_{}".format(files_dir, file_id, filename)

            with open(file_path, 'wb') as f:
                f.write(file_content)

            cur.execute("UPDATE files SET path = ? WHERE id = ?", (file_path, file_id))

            return file_id

    except Exception as e:
        app.logger.warn("Failed to write/update file {}: {}".format(file_path, e))
        if file_path is not None:
            try:
                os.unlink(file_path)
            except Exception:
                pass
        abort(http.ERROR_INTERNAL_SERVER_ERROR)


@app.post("/legacy/files")
def handle_legacy_store_file():
    user, room = legacy_check_user_room(write=True, upload=True)
    file_id = process_legacy_file_upload_for_room(user, room)
    return jsonify({'status_code': 200, 'result': file_id})


@app.post("/legacy/rooms/<Room:room>/image")
def handle_legacy_upload_room_image(room):
    user, room = legacy_check_user_room(write=True, upload=True, moderator=True)
    file_id = process_legacy_file_upload_for_room(user, room, lifetime=None)
    with db.conn:
        db.conn.execute("UPDATE rooms SET image = ? WHERE id = ?", [file_id, room.id])
    return jsonify({'status_code': 200, 'result': file_id})


@app.get("/legacy/files/<int:file_id>")
def handle_legacy_get_file(file_id):
    user, room = legacy_check_user_room(read=True)

    with db.conn as conn:
        result = conn.execute(
            "SELECT path FROM files WHERE room = ? AND id = ?", (room.id, file_id)
        )
        row = result.fetchone()
        if not row:
            abort(http.NOT_FOUND)

    with open(row[0], 'rb') as f:
        file_content = f.read()
    return jsonify({'status_code': 200, 'result': utils.encode_base64(file_content)})


@app.post("/legacy/delete_messages")
def handle_legacy_delete_messages():
    user, room = legacy_check_user_room(read=True)

    ids = request.json['ids']
    if len(ids) > 997:
        # 997 because we need two binds for room/user, 999 is the maximum number of bind parameters
        # for sqlite (pre-3.32), and because that's already a huge number of things to delete at
        # once.  (Older SOGS had no such limit, but that's insane).
        abort(http.BAD_REQUEST)

    in_params = ",".join("?" * len(ids))

    is_moderator = model.check_permission(user, room, moderator=True)

    with db.conn as conn:
        if not is_moderator:
            # If not a moderator then we only proceed if all of the messages are the user's own:
            res = conn.execute(
                """
                SELECT EXISTS(SELECT * FROM messages WHERE room = ? AND user != ? AND id IN ({}))
                """.format(
                    in_params
                ),
                [room.id, user.id, *ids],
            )
            if res.fetchone()[0]:
                abort(http.UNAUTHORIZED)

            conn.execute(
                """
                UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
                WHERE room = ? AND id IN ({})
                """.format(
                    in_params
                ),
                [room.id, *ids],
            )

    return jsonify({'status_code': 200})


def ban_checks():
    user, room = legacy_check_user_room(moderator=True)

    to_ban = model.User(session_id=request.json['public_key'], autovivify=True)

    # Global mods/admins aren't bannable at all (at the room level)
    if to_ban.global_moderator:
        app.logger.warn(
            "Cannot ban {} from {}: user is a global moderator".format(
                to_ban.session_id, room.token
            )
        )
        abort(http.FORBIDDEN)

    return user, room, to_ban


def apply_ban(conn, user, room, to_ban):
    is_mod = bool(
        conn.execute(
            "SELECT moderator FROM user_permissions WHERE room = ? AND user = ?",
            (room.id, to_ban.id),
        ).fetchone()[0]
    )

    if is_mod and not model.check_permission(user, room, admin=True):
        app.logger.warn(
            "Cannot ban {} from {}: the ban target is a room moderator, "
            "but the ban initiator ({}) is not an admin".format(
                to_ban.session_id, room.token, user.session_id
            )
        )
        abort(http.FORBIDDEN)

    conn.execute(
        """
        INSERT INTO user_permission_overrides (room, user, banned, moderator, admin)
        VALUES (?, ?, TRUE, FALSE, FALSE)
        ON CONFLICT DO UPDATE SET banned = TRUE, moderator = FALSE, admin = FALSE
        """,
        (room.id, to_ban.id),
    )


@app.post("/legacy/block_list")
def handle_legacy_ban():
    user, room, to_ban = ban_checks()

    with db.conn as conn:
        apply_ban(conn, user, room, to_ban)

    return jsonify({"status_code": 200})


@app.post("/legacy/ban_and_delete_all")
def handle_legacy_banhammer():
    user, room, to_ban = ban_checks()

    with db.conn as conn:
        apply_ban(conn, user, room, to_ban)

        cur = conn.cursor()
        cur.execute(
            """
            UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
            WHERE room = ? AND user = ?
            """,
            (room.id, to_ban.id),
        )

        posts_removed = cur.rowcount

        # We don't actually delete from disk right now, but clear the room (so that they aren't
        # retrievable) and set them to be expired (so that the next file pruning will delete them
        # from disk).
        cur.execute(
            "UPDATE files SET room = NULL, expiry = ? WHERE room = ? AND uploader = ?",
            (time.time(), room.id, to_ban.id),
        )
        files_removed = cur.rowcount

    app.logger.info(
        "Banned {} from room {}: {} messages and {} files deleted".format(
            to_ban.session_id, room.token, posts_removed, files_removed
        )
    )

    return jsonify({"status_code": 200})


@app.delete("/legacy/block_list/<SessionID:session_id>")
def handle_legacy_unban(session_id):
    user, room = legacy_check_user_room(moderator=True)

    try:
        to_unban = model.User(session_id=session_id, autovivify=False)
    except NoSuchUser:
        abort(http.NOT_FOUND)

    with db.conn as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE user_permission_overrides SET banned = FALSE WHERE room = ? AND user = ?",
            (room.id, to_unban.id),
        )
        updated = cur.rowcount

    if updated > 0:
        return jsonify({"status_code": 200})

    abort(http.NOT_FOUND)


@app.get("/legacy/block_list")
def handle_legacy_banlist():
    # Can't go through the usual legacy_check_user_room call here, because we want to continue here
    # even if we are banned:
    user, room = legacy_check_user_room(no_perms=True)

    # If you are a moderator then we show you everything; if you are banned we show you just
    # yourself; otherwise we show you nothing.
    row = db.conn.execute(
        "SELECT banned, moderator FROM user_permissions WHERE room = ? AND user = ?",
        (room.id, user.id),
    ).fetchone()
    banned, mod = bool(row[0]), bool(row[1])
    bans = []
    if banned:
        bans.append(user.session_id)
    elif mod:
        rows = db.conn.execute(
            "SELECT session_id FROM user_permissions WHERE room = ? AND banned", (room.id,)
        )
        bans = [row[0] for row in rows]
    return {"status_code": 200, "banned_members": bans}


@app.get("/legacy/moderators")
def handle_legacy_get_mods():
    user, room = legacy_check_user_room(read=True)

    mods = room.get_mods(user)
    return jsonify({"status_code": 200, "moderators": mods})


# Posting here adds an admin and requires admin access.  Legacy Session doesn't understand the
# moderator/admin distinction so we don't support moderator adjustment at all here.
@app.post("/legacy/moderators")
def handle_legacy_add_admin():
    user, room = legacy_check_user_room(admin=True)

    session_id = request.json["public_key"]
    if len(session_id) != 66 or not session_id.startswith("05"):
        abort(http.BAD_REQUEST)

    mod = model.User(session_id=session_id, autovivify=True)
    with db.conn as conn:
        conn.execute(
            """
            INSERT INTO user_permission_overrides (user, room, admin) VALUES (?, ?, TRUE)
            ON CONFLICT DO UPDATE SET admin = TRUE
            """,
            (mod.id, room.id),
        )

    app.logger.info("{} added admin {} to room {}".format(user.session_id, mod.session_id, room.token))
    return jsonify({"status_code": 200})


# DELETE here removes an admin or moderator and requires admin access.  (Legacy Session doesn't
# understand the moderator/admin distinction so we don't distinguish between them and just remove
# both powers, if present).
@app.delete("/legacy/moderators/<SessionID:session_id>")
def handle_legacy_remove_admin(session_id):
    user, room = legacy_check_user_room(admin=True)

    try:
        mod = model.User(session_id=session_id, autovivify=False)
    except NoSuchUser:
        abort(http.NOT_FOUND)

    with db.conn as conn:
        conn.execute(
            """
            UPDATE user_permission_overrides SET moderator = FALSE, admin = FALSE
            WHERE user = ? AND room = ?
            """,
            (mod.id, room.id),
        )

    app.logger.info(
        "{} removed moderator/admin {} from room {}".format(user.session_id, mod.session_id, room.token)
    )
    return jsonify({"status_code": 200})
