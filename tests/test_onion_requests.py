from sogs.web import app
from sogs import crypto
from sogs.hashing import blake2b
from sogs import utils
from nacl.bindings import (
    crypto_scalarmult,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
from Cryptodome.Cipher import AES
import nacl.utils
import struct
import json
import auth

from nacl.public import PrivateKey

# ephemeral X25519 keypair for use in tests
a = PrivateKey(bytes.fromhex('ec32fb5766cf52b1b5d7b0bff08e29f5c0c58ca19beaf6a5c7d3dd8ac7ced963'))
A = a.public_key
assert A.encode().hex() == 'd79a50b82ba8ca665f854382b42ba159efd16eef87409e97a8d07395b9492928'

# For xchacha20 with use the libsodium recommended shared key of H(aB || A || B), where H(.) is
# 32-byte Blake2B
shared_xchacha20_key = blake2b(
    (
        crypto_scalarmult(a.encode(), crypto.server_pubkey_bytes),
        A.encode(),
        crypto.server_pubkey_bytes,
    )
)

# AES-GCM onion requests were implemented using the somewhat weaker shared key of just aB:
shared_aes_key = crypto_scalarmult(a.encode(), crypto.server_pubkey_bytes)


def build_payload(inner_json, inner_body=None, *, v, enc_type, outer_json_extra={}):
    """Encrypt and encode a payload for sogs"""

    if not isinstance(inner_json, bytes):
        inner_json = json.dumps(inner_json).encode()

    if v == 3:
        assert inner_body is None
        inner_data = inner_json
    elif v == 4:
        inner_data = b''.join(
            (
                b'l',
                str(len(inner_json)).encode(),
                b':',
                inner_json,
                *(() if inner_body is None else (str(len(inner_body)).encode(), b':', inner_body)),
                b'e',
            )
        )
    else:
        raise RuntimeError(f"invalid payload v{v}")

    inner_enc = ()
    if enc_type in ("xchacha20", "xchacha20-poly1305"):
        # For xchacha20 we stick the nonce to the beginning of the encrypted blob
        nonce = nacl.utils.random(24)
        inner_enc = (
            nonce,
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                inner_data, aad=None, nonce=nonce, key=shared_xchacha20_key
            ),
        )
    elif enc_type in ("aes-gcm", "gcm"):
        # For aes-gcm we stick the iv on the beginning of the encrypted blob and the mac tag on the
        # end of it
        iv = nacl.utils.random(12)
        cipher = AES.new(shared_aes_key, AES.MODE_GCM, iv)
        enc, mac = cipher.encrypt_and_digest(inner_data)
        inner_enc = (iv, enc, mac)
    else:
        raise ValueError(f"Invalid enc_type: {enc_type}")

    # The outer request is in storage server onion request format:
    # [N][junk]{json}
    # where we load the fields for the last hop *and* the fields for sogs into the json.
    outer_json = {
        "host": "localhost",
        "port": 80,
        "protocol": "http",
        "target": f"/oxen/v{v}/lsrpc",
        "ephemeral_key": A.encode().hex(),
        "enc_type": enc_type,
        **outer_json_extra,
    }
    return b''.join(
        (
            struct.pack('<i', sum(len(x) for x in inner_enc)),
            *inner_enc,
            json.dumps(outer_json).encode(),
        )
    )


def decrypt_reply(data, *, v, enc_type):
    """
    Parses a reply; returns the json metadata and the body.  Note for v3 that there is only json;
    body will always be None.
    """
    if v == 3:
        data = utils.decode_base64(data)

    if enc_type in ("xchacha20", "xchacha20-poly1305"):
        assert len(data) > 24
        nonce, enc = data[:24], data[24:]
        data = crypto_aead_xchacha20poly1305_ietf_decrypt(
            enc, aad=None, nonce=nonce, key=shared_xchacha20_key
        )
    elif enc_type in ("aes-gcm", "gcm"):
        assert len(data) > 28
        iv, enc, mac = data[:12], data[12:-16], data[-16:]
        cipher = AES.new(shared_aes_key, AES.MODE_GCM, iv)
        data = cipher.decrypt_and_verify(enc, mac)
    else:
        raise ValueError(f"Invalid enc_type: {enc_type}")

    body = None

    if v == 4:
        assert (data[:1], data[-1:]) == (b'l', b'e')
        data = memoryview(data)[1:-1]
        json_data, data = utils.bencode_consume_string(data)
        json_ = json.loads(json_data.tobytes())
        if data:
            body, data = utils.bencode_consume_string(data)
            assert len(data) == 0
            body = body.tobytes()
    elif v == 3:
        json_ = json.loads(data)

    return json_, body


def test_v3(room, client):
    # Construct an onion request for /room/test-room
    req = {'method': 'GET', 'endpoint': '/room/test-room'}
    data = build_payload(req, v=3, enc_type="xchacha20")

    r = client.post("/loki/v3/lsrpc", data=data)

    assert r.status_code == 200

    room_info = decrypt_reply(r.data, v=3, enc_type="xchacha20")[0]

    assert room_info['description'] == 'Test suite testing room'
    assert 'moderator' not in room_info


def test_v3_authenticated(room, mod, client):
    # Construct an onion request for /room/test-room
    req = {'method': 'GET', 'endpoint': '/room/test-room'}
    req['headers'] = auth.x_sogs(mod.ed_key, crypto.server_pubkey, req['method'], req['endpoint'])
    data = build_payload(req, v=3, enc_type="xchacha20")

    r = client.post("/loki/v3/lsrpc", data=data)

    assert r.status_code == 200

    room_info = decrypt_reply(r.data, v=3, enc_type="xchacha20")[0]

    assert room_info['description'] == 'Test suite testing room'
    assert 'moderator' in room_info and room_info['moderator']


def test_v4(room, client):
    req = {'method': 'GET', 'endpoint': '/room/test-room'}
    data = build_payload(req, v=4, enc_type="xchacha20")

    r = client.post("/oxen/v4/lsrpc", data=data)

    assert r.status_code == 200

    info, body = decrypt_reply(r.data, v=4, enc_type="xchacha20")

    assert info == {'code': 200, 'headers': {'content-type': 'application/json'}}

    room_info = json.loads(body)
    assert room_info['description'] == 'Test suite testing room'
    assert 'moderator' not in room_info


def test_v4_authenticated(room, mod, client):
    req = {'method': 'GET', 'endpoint': '/room/test-room'}
    req['headers'] = auth.x_sogs(mod.ed_key, crypto.server_pubkey, req['method'], req['endpoint'])
    data = build_payload(req, v=4, enc_type="xchacha20")

    r = client.post("/oxen/v4/lsrpc", data=data)

    assert r.status_code == 200

    info, body = decrypt_reply(r.data, v=4, enc_type="xchacha20")

    assert info == {'code': 200, 'headers': {'content-type': 'application/json'}}

    room_info = json.loads(body)
    assert room_info['description'] == 'Test suite testing room'
    assert 'moderator' in room_info and room_info['moderator']


@app.post("/test_v4_post_body")
def v4_post_body():
    from flask import request, jsonify, Response

    if request.is_json:
        return jsonify({"json": request.json})
    return Response(
        f"not json ({request.content_type}): {request.data.decode()}".encode(),
        mimetype='text/plain',
    )


def test_v4_post_body(room, user, client):
    req = {'method': 'POST', 'endpoint': '/test_v4_post_body'}
    content = b'test data'
    req['headers'] = auth.x_sogs(
        user.ed_key, crypto.server_pubkey, req['method'], req['endpoint'], body=content
    )
    req['headers']['content-type'] = 'text/plain'

    data = build_payload(req, content, v=4, enc_type="xchacha20")

    r = client.post("/oxen/v4/lsrpc", data=data)

    assert r.status_code == 200

    info, body = decrypt_reply(r.data, v=4, enc_type="xchacha20")

    assert (info, body) == (
        {'code': 200, 'headers': {'content-type': 'text/plain; charset=utf-8'}},
        b'not json (text/plain): test data',
    )

    # Now try with json:
    test_json = {"test": ["json", None], "1": 23}
    content = json.dumps(test_json).encode()
    req['headers'] = auth.x_sogs(
        user.ed_key, crypto.server_pubkey, req['method'], req['endpoint'], body=content
    )
    req['headers']['content-type'] = 'application/json'
    data = build_payload(req, content, v=4, enc_type="xchacha20")
    r = client.post("/oxen/v4/lsrpc", data=data)

    assert r.status_code == 200

    info, body = decrypt_reply(r.data, v=4, enc_type="xchacha20")

    assert info == {'code': 200, 'headers': {'content-type': 'application/json'}}
    assert json.loads(body) == {"json": test_json}

    # Now try with json, but with content-type set to something else (this should avoid the json
    req['headers'] = auth.x_sogs(
        user.ed_key, crypto.server_pubkey, req['method'], req['endpoint'], body=content
    )
    req['headers']['content-type'] = 'x-omg/all-your-base'
    data = build_payload(req, content, v=4, enc_type="xchacha20")
    r = client.post("/oxen/v4/lsrpc", data=data)

    assert r.status_code == 200

    info, body = decrypt_reply(r.data, v=4, enc_type="xchacha20")

    assert info == {'code': 200, 'headers': {'content-type': 'text/plain; charset=utf-8'}}
    assert body == b'not json (x-omg/all-your-base): ' + content


@app.put("/test_encoding/<path:p>")
def onion_test_encoding_endpoint(p):
    from flask import jsonify

    return jsonify({"p": p})


def test_onion_url_encoding(room, user, client):
    req1 = {'method': 'PUT', 'endpoint': "/test_encoding/%E2%9D%A4%EF%B8%8F"}
    req2 = {'method': 'PUT', 'endpoint': "/test_encoding/❤️"}

    # The signature should be on the URL-decoded value, and so with the same nonce we should get the
    # same signature for the two requests above.  (We can't submit them for the test below, though,
    # because we'd hit the nonce replay filter).
    def fixed_sig(req):
        return auth.x_sogs(
            user.ed_key,
            crypto.server_pubkey,
            req['method'],
            req['endpoint'],
            body=b'{}',
            nonce=b'0123456789abcdef',
        )['X-SOGS-Signature']

    assert fixed_sig(req1) == fixed_sig(req2)

    for req in (req1, req2):
        req['headers'] = auth.x_sogs(
            user.ed_key, crypto.server_pubkey, req['method'], req['endpoint'], body=b'{}'
        )
        req['headers']['content-type'] = 'application/json'

    data1 = build_payload(req1, b'{}', v=4, enc_type="xchacha20")
    data2 = build_payload(req2, b'{}', v=4, enc_type="xchacha20")

    r = client.post("/oxen/v4/lsrpc", data=data1)
    assert r.status_code == 200
    info, body = decrypt_reply(r.data, v=4, enc_type="xchacha20")
    assert info == {'code': 200, 'headers': {'content-type': 'application/json'}}
    assert json.loads(body) == {"p": "❤️"}

    r = client.post("/oxen/v4/lsrpc", data=data2)
    assert r.status_code == 200
    info, body = decrypt_reply(r.data, v=4, enc_type="xchacha20")
    assert info == {'code': 200, 'headers': {'content-type': 'application/json'}}
    assert json.loads(body) == {"p": "❤️"}
