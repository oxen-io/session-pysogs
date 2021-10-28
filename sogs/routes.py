from flask import abort, request, jsonify, send_file, render_template
from .web import app
from . import crypto
from . import model
from . import db
from . import utils
from . import config

import json
import random

@app.route("/")
def serve_index():
    rooms = model.get_rooms()
    if len(rooms) == 0:
        return render_template('setup.html')
    room = random.choice(rooms).get('name')
    return render_template("index.html", url_base=config.URL_BASE, room=room, pubkey=crypto.server_pubkey_hex)


@app.route("/rooms")
def get_rooms():
    """ serve room list """
    return jsonify(model.get_rooms())

@app.route("/room/<room_id>")
def get_room_info(room_id):
    """ serve room metadata """
    fallback = dict()
    room = model.get_room(room_id)
    room_info = room and room.json() or fallback
    return jsonify(room_info)

@app.route("/room/<room_id>/image")
def serve_room_image(room_id):
    """ serve room icon """
    filename = None
    with db.pool as conn:
        result = conn.execute("SELECT filename FROM files WHERE id IN ( SELECT image FROM rooms WHERE token = ? )", room_id)
        filename = result.fetchone()
    if not filename:
        abort(404)
    return send_file(filename)

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
        rows = conn.execute("SELECT messages.*, user.session_id, FROM messages WHERE messages.room IN ( SELECT id FROM rooms WHERE token = ?1 ) JOIN users ON messages.user = users.id WHERE data IS NOT NULL ORDER BY id ASC LIMIT ?2", room_id, limit)
        for row in rows:
            msgs += {'posted': row[3], 'edited': row[4], 'updated': row[5], 'message': row[6], 'signature': row[8], 'session_id': row[9]}
    return msgs


# --- BEGIN OLD API ---

def get_user_from_token(token):
    """
    get user model from database given a token
    """
    if not token.startswith('05'):
        return
    token = utils.decode_hex_or_b64(token)
    if len(token) == (SESSION_ID_SIZE + SIG_SIZE):
        data, sig = token[0:SESSION_ID_SIZE], token[SESSION_ID_SIZE:SIG_SIZE]
        try:
            crypto.verify_sig_from_server(data, sig)
        except:
            abort(400)
        else:
            return model.get_user(hex(data))

def get_user_from_auth_header(headers):
    return headers and get_user_from_token(headers.get("Authorization", None)) or None

def handle_onionreq_plaintext(plaintext):
    """
    given a plaintext from a junk, parse it, handle the request and give the reply plaintext to encrypt
    """
    obj = json.loads(plaintext)

    sig = utils.decode_hex_or_b64(obj.get('signature'))
    if sig is None:
        abort(400)
    data = bytearray().join([obj.get(part).encode() for part in ['endpoint', 'method', 'body', 'nonce']])
    pk = utils.decode_hex_or_b64(obj.get('ed25519_pubkey'))

    try:
        crypto.verify_sig_from_pk(data, sig, pk)
    except:
        # invalid sig
        abort(403)

    ep = obj.get('endpoint')
    if not ep:
        # no endpoint?
        abort(404)
    # ensure prefix of /
    if ep[0] != '/':
        ep = '/{}'.format(ep)

    endpoint = urlparse(ep)
    user = get_user_from_auth_header(obj.get('headers', None))
    methods = {
        "GET": handle_deprecated_get,
        "POST": handle_deprecated_post,
        "DELETE": handle_deprecated_delete
    }
    func = methods.get(obj.get("method"))
    if not func:
        abort(400)
    ret = func(obj.get("room"), endpoint.path, user, endpoint.query, obj.get("body"))
    if not ret:
        abort(500)
    return json.dumps(ret)

def handle_deprecated_get(room_id, path, user, query_params, body):
    path_parts = path.split('/')
    if path_parts[0] == 'rooms':
        plen = len(path_parts)
        if plen == 1:
            return model.get_rooms()
        if plen == 2:
            return model.get_room(path_parts[1])
        if path_parts[-1] == 'image' and plen == 3:
            return model.get_room_image_json_blob(path_parts[1])

def handle_comapct_poll(user, req):
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

def handle_deprecated_post(room_id, path, user, query_params, body):
    path_parts = path.split('/')
    if path == '/compact_poll':
        req = json.loads(body)
        results = list()
        for shit in req.get('requests'):
            results.append(handle_compact_poll(user, shit))
        return {'status_code': 200, 'results': result}

def handle_deprecated_delete(room_id, path, user, query_params, body):
    pass


@app.route("/loki/v3/lsrpc", methods=["POST"])
def handle_onionreq():
    """
    parse an onion request and process the request, shit out the reply after encrypting it
    """
    junk = None
    try:
        junk = crypto.parse_junk(request.data)
    except:
        pass
    if junk:
        return junk.transform_reply(handle_onionreq_plaintext(junk.payload))
    abort(400)
