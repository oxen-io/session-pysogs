from flask import abort, request, jsonify, send_file, render_template, Response
from .web import app
from . import crypto
from . import model
from . import db
from . import utils
from . import config

import json
import random

from io import BytesIO

import qrencode

from PIL.Image import NEAREST

@app.route("/")
def serve_index():
    rooms = model.get_rooms()
    if len(rooms) == 0:
        return render_template('setup.html')
    return render_template("index.html", url_base=config.URL_BASE, rooms=rooms, pubkey=crypto.server_pubkey_hex)


@app.route("/legacy/rooms")
def get_rooms():
    """ serve room list """
    return jsonify(model.get_rooms())

@app.route("/legacy/rooms/<room_id>")
def get_room_info(room_id):
    """ serve room metadata """
    room = model.get_room(room_id)
    if not room:
        abort(404)
    room_info = {'id': room.get('token'), 'name': room.get('name'), 'image_id': None}
    return jsonify({'room': room_info, 'status_code': 200})

@app.route("/legacy/rooms/<room_id>/image")
def serve_room_image(room_id):
    """ serve room icon """
    filename = None
    with db.pool as conn:
        result = conn.execute("SELECT filename FROM files WHERE id IN ( SELECT image FROM rooms WHERE token = ? )", [room_id])
        filename = result.fetchone()
    if not filename:
        abort(404)
    return send_file(filename)

@app.route("/view/room/<room_id>")
def view_room(room_id):
    room = model.get_room(room_id)
    if room is None:
        abort(404)
    return render_template("view_room.html", room=room.get('token'))

@app.route("/view/<room_id>/invite.png")
def serve_invite_qr(room_id):
    room = model.get_room(room_id)
    if not room:
        abort(404)
    img = qrencode.encode(utils.server_url(room.get('token')))
    data = BytesIO()
    img = img[-1].resize((512,512), NEAREST)
    img.save(data, "PNG")
    return Response(data.getvalue(), mimetype="image/png")

@app.route("/room/<room_id>/message", methods=["POST"])
def post_to_room(room_id):
    user = utils.get_session_id(request)

@app.route("/room/<room_id>/messages/recent")
def get_recent_room_messages(room_id):
    """ get list of recent messages """
    msgs = list()
    # TODO: pass in via query paramter
    limit = 100
    with db.pool as conn:
        rows = conn.execute("SELECT messages.*, users.session_id FROM messages JOIN users ON messages.user = users.id WHERE data IS NOT NULL AND messages.room IN ( SELECT id FROM rooms WHERE token = ?1 ) ORDER BY id ASC LIMIT ?2", [room_id, limit])
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
    if not token.startswith('05'):
        return
    token = utils.decode_hex_or_b64(token)
    if len(token) == (SESSION_ID_SIZE + SIG_SIZE):
        data, sig = token[0:SESSION_ID_SIZE], token[SESSION_ID_SIZE:SIG_SIZE]
        try:
            crypto.server_sign(data, sig)
        except:
            abort(400)
        else:
            return model.get_user(hex(data))

def get_user_from_auth_header(headers=None):
    if headers is None:
        headers = request.headers
    return get_user_from_token(headers.get("Authorization", None)) or None

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
            abort(403)

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


@app.route("/legacy/auth_token_challenge")
def auth_token_challenge():
    pubkey = request.args.get("public_key")
    token = utils.make_legacy_token(pubkey)
    pk = utils.decode_hex_or_b64(pubkey[2:])
    app.logger.warn("pk={}".format(len(pk)))
    ct = crypto.server_encrypt(pk, token)
    return jsonify({'ciphertext': utils.encode_base64(ct), 'ephemeral_pubkey': crypto.server_pubkey_base64})

@app.route("/legacy/compact_poll", methods=["POST"])
def handle_comapct_poll():
    req = request.json
    user = get_user_from_auth_header()
    if not user:
        return {'status_code': 500, 'error': 'no user provided'}
    room_id = req.get('room_token')
    if not room_id:
        return {'status_code': 500, 'error': 'no room provided'}

    if not model.user_read_allowed(user, room_id):
        return {'status_code': 500, 'error': 'read access not permitted'}

    result = {'room_id': room_id, 'status_code': 200}

    messages = model.get_message_deprecated(room_id, req.get('from_message_server_id'))

    messages = model.get_deletion_deprecated(room_id, req.get('from_deletion_server_id'))

    mods = model.get_mods_for_room(room_id)

    return {'status_code': 200, 'room_id': room_id, 'messages': messages, 'deletions': deletions, 'moderators': mods}


@app.route("/loki/v3/lsrpc", methods=["POST"])
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
