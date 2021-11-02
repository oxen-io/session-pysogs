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
        abort(404)
    return render_template("view_room.html", room=room.get('token'), room_url=utils.server_url(room.get('token')))

@app.get("/view/<RoomToken:room_token>/invite.png")
def serve_invite_qr(room_token):
    room = model.get_room(room_token)
    if not room:
        abort(404)
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
    msgs = list()
    # TODO: pass in via query paramter
    limit = 100
    with db.pool as conn:
        rows = conn.execute("SELECT messages.*, users.session_id FROM messages JOIN users ON messages.user = users.id WHERE data IS NOT NULL AND messages.room IN ( SELECT id FROM rooms WHERE token = ?1 ) ORDER BY id ASC LIMIT ?2", [room_token, limit])
        for row in rows:
            msgs += {'posted': row[3], 'edited': row[4], 'updated': row[5], 'message': row[6], 'signature': row[8], 'session_id': row[9]}
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
        abort(400)
    else:
        return model.get_user(token) or dict()

def handle_onionreq_plaintext(junk):
    """
    given a plaintext from a junk, parse it, handle the request and give the reply plaintext to encrypt
    """
    obj = json.loads(junk.payload)

    sig = utils.decode_hex_or_b64(obj.get('signature', None))
    if sig:
        data = bytearray().join([obj.get(part).encode() for part in ['endpoint', 'method', 'body', 'nonce']])
        pk = utils.decode_hex_or_b64(obj.get('ed25519_pubkey'))

        try:
            crypto.verify_sig_from_pk(data, sig, pk)
        except:
            # invalid sig
            abort(http.FORBIDDEN)

    cl = None
    ct = None
    subreq_body = None
    meth, target = obj['method'], obj['endpoint']
    if '?' in target:
        target, query_string = target.split('?', 1)
    else:
        query_string = ''

        subreq_body = obj.get('body', '').encode()
        if meth in ('POST', 'PUT'):
            ct = obj.get('contentType', 'application/json')
            cl = len(subreq_body)
        subreq_body = BytesIO(subreq_body)

    if target[0] != '/':
        target = '/legacy/{}'.format(target)

    # Set up the wsgi environ variables for the subrequest (see PEP 0333)
    subreq_env = {
        **request.environ,
        "REQUEST_METHOD": meth,
        "PATH_INFO": target,
        "QUERY_STRING": query_string,
        "CONTENT_TYPE": ct,
        "CONTENT_LENGTH": cl,
        **{'HTTP_{}'.format(h.upper().replace('-', '_')): v for h, v in obj.get('headers', {}).items()},
        'wsgi.input': subreq_body
    }

    with app.request_context(subreq_env) as subreq_ctx:
        response = app.full_dispatch_request()
        data = response.get_data()
        app.logger.warn("response data: {}".format(data))
        crap = junk.transformReply(data)
        app.logger.warn("junk={}".format(crap))
        return utils.encode_base64(crap)


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


@app.post("/loki/v3/lsrpc")
def handle_onionreq():
    """
    parse an onion request and process the request, shit out the reply after encrypting it
    """
    data = request.data
    app.logger.warn("content length: {}".format(request.headers.get("Content-Length")))
    app.logger.warn("content type: {}".format(request.headers.get("Content-Type")))
    app.logger.warn("request data: {}".format(data))
    junk = crypto.parse_junk(data)

    app.logger.warn("got junk payload: {}".format(junk.payload))
    return handle_onionreq_plaintext(junk)
