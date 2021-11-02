from flask import abort, request, jsonify, send_file, render_template, Response
from .web import app
from . import crypto
from . import model
from . import db
from . import utils
from . import config
from . import http

import json
import random

from werkzeug.routing import BaseConverter

from io import BytesIO

import qrencode

from PIL.Image import NEAREST

class RoomTokenConverter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = "[\w-]{1,64}"

app.url_map.converters['RoomToken'] = RoomTokenConverter

@app.get("/")
def serve_index():
    rooms = model.get_rooms()
    if len(rooms) == 0:
        return render_template('setup.html')
    return render_template("index.html", url_base=config.URL_BASE, rooms=rooms, pubkey=crypto.server_pubkey_hex)


@app.get("/legacy/rooms")
def get_rooms():
    """ serve room list """
    return jsonify(model.get_rooms())

@app.get("/legacy/rooms/<RoomToken:room_token>")
def get_room_info(room_token):
    """ serve room metadata """
    room = model.get_room(room_token)
    if not room:
        abort(http.NOT_FOUND)
    room_info = {'id': room.get('token'), 'name': room.get('name'), 'image_id': None}
    return jsonify({'room': room_info, 'status_code': 200})

@app.get("/legacy/rooms/<RoomToken:room_token>/image")
def serve_room_image(room_token):
    """ serve room icon """
    filename = None
    with db.pool as conn:
        result = conn.execute("SELECT path FROM files WHERE id = (SELECT image FROM rooms WHERE token = ?)", [room_token])
        filename = result.fetchone()
    if not filename:
        abort(http.NOT_FOUND)
    return send_file(filename)

@app.get("/view/room/<RoomToken:room_token>")
def view_room(room_token):
    room = model.get_room(room_token)
    if room is None:
        abort(http.NOT_FOUND)
    return render_template("view_room.html", room=room.get('token'), room_url=utils.server_url(room.get('token')))

@app.get("/view/<RoomToken:room_token>/invite.png")
def serve_invite_qr(room_token):
    room = model.get_room(room_token)
    if not room:
        abort(http.NOT_FOUND)
    img = qrencode.encode(utils.server_url(room.get('token')))
    data = BytesIO()
    img = img[-1].resize((512,512), NEAREST)
    img.save(data, "PNG")
    return Response(data.getvalue(), mimetype="image/png")

@app.post("/room/<RoomToken:room_token>/message")
def post_to_room(room_token):
    user = utils.get_session_id(request)

@app.get("/room/<RoomToken:room_token>/messages/recent")
def get_recent_room_messages(room_token):
    """ get list of recent messages """
    if 'public_key' in request.args:
        limit = int(request.args['public_key'])
        if not 1 <= limit <= 255:
            abort(http.BAD_REQUEST)
    else:
        limit = 100

    msgs = list()
    with db.pool as conn:
        rows = conn.execute("""
            SELECT
                messages.id, session_id, posted, edited, data, data_size, signature
            FROM messages JOIN users ON messages.user = users.id
            WHERE messages.room = (SELECT id FROM rooms WHERE token = ?1)
                AND data IS NOT NULL
            ORDER BY id DESC LIMIT ?2
            """,
            (room_token, limit))
        for id, session_id, posted, edited, data, data_size, signature in rows:
            m = { 'id': id, 'session_id': session_id, 'timestamp': posted, 'signature': utils.encode_base64(signature) }
            if edited is not None:
                m['edited'] = edited
            if len(data) < data_size:
                # Re-pad the message (we strip off padding when storing)
                data += b'\x00' * (data_size - len(data))
            m['data'] = utils.encode_base64(data)
            msgs += m

    return jsonify(msgs)


# --- BEGIN OLD API ---

def get_user_from_token(token):
    """
    get user model from database given a token
    """

    if not token:
        return

    try:
        rawtoken = utils.decode_hex_or_b64(token, utils.LEGACY_TOKEN_SIZE)
        app.logger.warn('token={}'.format(rawtoken))
        crypto.server_verify(rawtoken)
    except Exception as ex:
        app.logger.error("failed to decode/verify token: {}".format(ex))
        abort(http.UNAUTHORIZED)
    else:
        return model.get_user(token) or dict()



@app.post("/legacy/claim_auth_token")
def claim_auth():
    return jsonify({'status_code':200})

@app.get("/legacy/auth_token_challenge")
def auth_token_challenge():
    pubkey = request.args.get("public_key")
    if len(pubkey) != 66 or not pubkey.startswith('05'):
        abort(http.BAD_REQUEST)
    token = utils.make_legacy_token(pubkey)
    pk = utils.decode_hex_or_b64(pubkey[2:], 32)
    app.logger.warn("token={} pk={}".format(token, pk))
    ct = crypto.server_encrypt(pk, token)
    assert len(ct) == utils.LEGACY_TOKEN_SIZE
    return jsonify({'status_code': 200, 'challenge': {'ciphertext': utils.encode_base64(ct), 'ephemeral_public_key': crypto.server_pubkey_base64}})

@app.post("/legacy/compact_poll")
def handle_comapct_poll():
    req_list = request.json
    result = list()
    for req in req_list.get('requests', list()):
        result.append(handle_one_compact_poll(req))
    return jsonify(result)

def handle_one_compact_poll(req):
    app.logger.warn("req={}".format(req))
    user = get_user_from_token(req.get('auth_token'))
    #if not user:
    #    return {'status_code': 500, 'error': 'no user provided'}
    room_token = req.get('room_id')
    if not room_token:
        return {'status_code': 500, 'error': 'no room provided'}

    #if not model.user_read_allowed(user, room_token):
    #    return {'status_code': 500, 'error': 'read access not permitted'}

    messages = model.get_message_deprecated(room_token, req.get('from_message_server_id'))

    deletions = model.get_deletions_deprecated(room_token, req.get('from_deletion_server_id'))

    mods = model.get_mods_for_room(room_token)

    return {'status_code': 200, 'room_id': room_token, 'messages': messages, 'deletions': deletions, 'moderators': mods}
