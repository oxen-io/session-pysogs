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

    def to_python(self, value):
        room = model.get_room(value)
        if room is None:
            raise ValidationError()
        return room

    def to_value(self, value):
        return value.get('token')


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

@app.get("/legacy/rooms/<RoomToken:room>")
def get_room_info(room):
    """ serve room metadata """
    room_info = {'id': room.get('token'), 'name': room.get('name')}
    return jsonify({'room': room_info, 'status_code': 200})

@app.get("/legacy/rooms/<RoomToken:room>/image")
def serve_room_image(room):
    """ serve room icon """
    filename = None
    with db.pool as conn:
        result = conn.execute("SELECT path FROM files WHERE id = (SELECT image FROM rooms WHERE token = ?)", [room.get('token')])
        filename = result.fetchone()
    if not filename:
        abort(http.NOT_FOUND)
    return send_file(filename)

@app.get("/view/room/<RoomToken:room>")
def view_room(room):
    return render_template("view_room.html", room=room.get('token'), room_url=utils.server_url(room.get('token')))

@app.get("/view/<RoomToken:room>/invite.png")
def serve_invite_qr(room):
    img = qrencode.encode(utils.server_url(room.get('token')))
    data = BytesIO()
    img = img[-1].resize((512,512), NEAREST)
    img.save(data, "PNG")
    return Response(data.getvalue(), mimetype="image/png")

@app.post("/room/<RoomToken:room>/message")
def post_to_room(room):
    user = utils.get_session_id(request)
    if not user:
        # todo: correct handling
        abort(http.FORBIDDEN)



@app.get("/room/<RoomToken:room>/messages/recent")
def get_recent_room_messages(room):
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
            ORDER BY messages.id DESC LIMIT ?2
            """,
            (room.get('token'), limit))
        for id, session_id, posted, edited, data, data_size, signature in rows:
            m = { 'id': id, 'session_id': session_id, 'timestamp': posted, 'signature': utils.encode_base64(signature) }
            if edited is not None:
                m['edited'] = edited
            if len(data) < data_size:
                # Re-pad the message (we strip off padding when storing)
                data += b'\x00' * (data_size - len(data))
            m['data'] = utils.encode_base64(data)
            msgs.append(m)

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
        crypto.server_verify(rawtoken)
    except Exception as ex:
        app.logger.error("failed to decode/verify token: {}".format(ex))
        abort(http.UNAUTHORIZED)
    else:
        session_id = utils.encode_hex(rawtoken[utils.SIGNATURE_SIZE:])
        return model.get_user(session_id)



@app.post("/legacy/claim_auth_token")
def claim_auth():
    return jsonify({'status_code':200})

@app.get("/legacy/auth_token_challenge")
def auth_token_challenge():
    pubkey = request.args.get("public_key")
    if len(pubkey) != (utils.SESSION_ID_SIZE * 2) or not pubkey.startswith('05'):
        abort(http.BAD_REQUEST)
    token = utils.make_legacy_token(pubkey)
    pk = utils.decode_hex_or_b64(pubkey[2:], 32)
    ct = crypto.server_encrypt(pk, token)

    model.ensure_user_exists(session_id=pubkey)

    return jsonify({'status_code': 200, 'challenge': {'ciphertext': utils.encode_base64(ct), 'ephemeral_public_key': crypto.server_pubkey_base64}})

@app.post("/legacy/messages")
def handle_post_legacy_message():
    room = model.get_room(request.headers.get("Room"))
    if not room:
        abort(http.NOT_FOUND)
    token = request.headers.get("Authorization")
    if not token:
        abort(http.FORBIDDEN)
    user = get_user_from_token(token)
    if not user:
        abort(http.NOT_AUTHORIZED)
    req = request.json
    data = utils.decode_base64(req.get('data'))
    sig = utils.decode_base64(req.get('signature'))
    msg = model.add_post_to_room(user.get('id'), room.get('id'), data, sig)
    if not msg:
        abort(http.TOO_MANY_REQUESTS)
    msg['public_key'] = user.get("session_id")
    msg['data'] = req.get('data')
    msg['signature'] = req.get('signature')
    return jsonify({'status_code':200, 'message': msg})



@app.post("/legacy/compact_poll")
def handle_comapct_poll():
    req_list = request.json
    result = list()
    for req in req_list.get('requests', list()):
        result.append(handle_one_compact_poll(req))
    return jsonify({'status_code': 200, 'results': result})

def handle_one_compact_poll(req):
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
