from flask import abort, request, jsonify, send_file
from .web import app
from . import crypto
from . import model
from . import db
from . import utils
from . import config
from . import http


# Legacy endpoints, to eventually be deleted.  These are invoked automatically if the client invokes
# an endpoint (via onion request) that doesn't start with a `/` -- we prepend `/legacy/` and submit
# it as an internal request to land here.


@app.get("/legacy/rooms")
def get_rooms():
    """serve room list"""
    return jsonify(model.get_rooms())


@app.get("/legacy/rooms/<RoomToken:room>")
def get_room_info(room):
    """serve room metadata"""
    room_info = {'id': room.get('token'), 'name': room.get('name')}
    return jsonify({'room': room_info, 'status_code': 200})


@app.get("/legacy/rooms/<RoomToken:room>/image")
def serve_room_image(room):
    """serve room icon"""
    filename = None
    with db.conn as conn:
        result = conn.execute(
            "SELECT path FROM files WHERE id = (SELECT image FROM rooms WHERE token = ?)",
            [room.get('token')],
        )
        filename = result.fetchone()
    if not filename:
        abort(http.NOT_FOUND)
    return send_file(filename)


# --- BEGIN OLD API ---


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
        return utils.encode_hex(rawtoken[utils.SIGNATURE_SIZE :])


def legacy_verify_room_access(pubkey, **perms):
    """
    For a legacy endpoint verifying a user is allowed to access a room calls flask.abort to bail out
    if the user is not allowed, otherwise returns the room info.
    """
    if not pubkey:
        abort(http.BAD_REQUEST)
    if len(pubkey) != (utils.SESSION_ID_SIZE * 2) or not pubkey.startswith('05'):
        abort(http.BAD_REQUEST)

    room = model.get_room(request.headers.get("Room"))
    if not room:
        abort(http.NOT_FOUND)

    if not model.check_permission(pubkey, room.get("id"), **perms):
        abort(http.FORBIDDEN)

    return room


def legacy_check_user_room(**perms):
    """
    Wraps legacy_verify_room_access to retrieve (and validate) the pubkey from the Authorization
    header.  Returns a pair of the user and room info dicts; aborts on any failure.
    """
    pubkey = get_pubkey_from_token(request.headers.get("Authorization"))
    room = legacy_verify_room_access(pubkey, **perms)
    user = model.get_user(pubkey)
    if not user:
        abort(http.NOT_AUTHORIZED)

    return (user, room)


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

    pubkey = request.args.get("public_key")

    legacy_verify_room_access(pubkey)

    token = utils.make_legacy_token(pubkey)
    pk = utils.decode_hex_or_b64(pubkey[2:], 32)
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
    msg = model.add_post_to_room(user.get('id'), room.get('id'), data, sig)
    if not msg:
        abort(http.TOO_MANY_REQUESTS)
    msg['public_key'] = user.get("session_id")
    msg['data'] = req.get('data')
    msg['signature'] = req.get('signature')
    return jsonify({'status_code': 200, 'message': msg})


@app.get("/legacy/messages")
def handle_legacy_get_messages():
    from_id = request.args.get('from_server_id')
    limit = utils.get_int_param('limit', 256, min=1, max=256, truncate=True)

    user, room = legacy_check_user_room(read=True)

    return jsonify(
        {'status_code': 200, 'messages': model.get_message_deprecated(room['id'], from_id, limit)}
    )


@app.post("/legacy/compact_poll")
def handle_comapct_poll():
    req_list = request.json
    result = list()
    for req in req_list.get('requests', list()):
        result.append(handle_one_compact_poll(req))
    return jsonify({'status_code': 200, 'results': result})


def handle_one_compact_poll(req):
    pk = get_pubkey_from_token(req.get('auth_token'))
    if not pk:
        return {'status_code': http.BAD_REQUEST, 'error': 'no auth_token provided'}
    room_token = req.get('room_id')
    if not room_token:
        return {'status_code': http.BAD_REQUEST, 'error': 'no room provided'}
    room = model.get_room(room_token)
    if not room:
        abort(http.NOT_FOUND)
    if not model.check_permission(pk, room['id'], read=True):
        abort(http.FORBIDDEN)

    messages = model.get_message_deprecated(room['id'], req.get('from_message_server_id'))

    deletions = model.get_deletions_deprecated(room['id'], req.get('from_deletion_server_id'))

    mods = model.get_mods_for_room(room['id'], pk)

    return {
        'status_code': 200,
        'room_id': room_token,
        'messages': messages,
        'deletions': deletions,
        'moderators': mods,
    }


@app.post("/legacy/files")
def handle_legacy_store_file():
    user, room = legacy_check_user_room(write=True, upload=True)

    import os
    import time

    # Slamming this all into memory is not very nice, but there's no terribly elegant way to get
    # around it when we have b64 input for legacy uploads.
    file_b64 = request.json['file']
    file_content = utils.decode_base64(file_b64)

    if len(file_content) > config.UPLOAD_FILE_MAX_SIZE:
        abort(http.ERROR_PAYLOAD_TOO_LARGE)

    files_dir = "uploads/" + room['token']
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
            expiry = time.time() + config.UPLOAD_DEFAULT_EXPIRY_DAYS * 86400

            # Insert the file row first, but with nonsense path because we want to put the ID in the
            # path, which we won't have until after the insert; we'll come back and update it.
            cur = db.conn.cursor()
            cur.execute(
                """
                INSERT INTO files (room, uploader, size, expiry, filename, path)
                VALUES (?, ?, ?, ?, ?, 'tmp')
                """,
                (room['id'], user['id'], len(file_content), expiry, filename),
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

    except Exception as e:
        app.logger.warn("Failed to write/update file {}: {}".format(file_path, e))
        if file_path is not None:
            try:
                os.unlink(file_path)
            except:
                pass
        abort(http.ERROR_INTERNAL_SERVER_ERROR)

    return jsonify({'status_code': 200, 'result': file_id})


@app.get("/legacy/files/<int:file_id>")
def handle_legacy_get_file(file_id):
    user, room = legacy_check_user_room(read=True)

    with db.conn as conn:
        result = conn.execute(
            "SELECT path FROM files WHERE room = ? AND id = ?", (room['id'], file_id)
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

    is_moderator = model.check_permission(user['session_id'], room['id'], moderator=True)

    with db.conn as conn:
        if not is_moderator:
            # If not a moderator then we only proceed if all of the messages are the user's own:
            res = conn.execute(
                """
                SELECT EXISTS(SELECT * FROM messages WHERE room = ? AND user != ? AND id IN ({}))
                """.format(
                    in_params
                ),
                [room['id'], user['id'], *ids],
            )
            if res.fetchone()[0]:
                abort(http.NOT_AUTHORIZED)

            conn.execute(
                """
                UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
                WHERE room = ? AND id IN ({})
                """.format(
                    in_params
                ),
                [room['id'], *ids],
            )

    return jsonify({'status_code': 200})
