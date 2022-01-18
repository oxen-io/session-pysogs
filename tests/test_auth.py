from sogs.web import app
from sogs.crypto import server_pubkey
import sogs.utils

from hashlib import blake2b
import json
from nacl.bindings import crypto_scalarmult
from nacl.public import PublicKey, PrivateKey
from nacl.utils import random
import time
from typing import Optional


def nonce():
    return random(16)


def x_sogs_raw(
    a: PrivateKey,
    A: PublicKey,
    B: PublicKey,
    method: str,
    full_path: str,
    body: Optional[bytes] = None,
    b64_nonce: bool = True,
    id_prefix: str = '05',
    timestamp_off: int = 0,
):
    """
    Calculates X-SOGS-* headers.

    Returns 4 elements: the headers dict, the nonce bytes, timestamp int, and hash bytes.

    Use x_sogs(...) instead if you don't need the nonce/timestamp/hash values.
    """
    n = nonce()
    ts = int(time.time()) + timestamp_off

    a_bytes, A_bytes, B_bytes = (x.encode() for x in (a, A, B))

    h = {
        'X-SOGS-Pubkey': id_prefix + A_bytes.hex(),
        'X-SOGS-Nonce': sogs.utils.encode_base64(n) if b64_nonce else n.hex(),
        'X-SOGS-Timestamp': str(ts),
    }

    # Deliberately using hashlib (rather than nacl) here to use an independent blake2b
    # implementation from the sogs code.
    shared_key = blake2b(
        crypto_scalarmult(a_bytes, B_bytes) + A_bytes + B_bytes,
        digest_size=64,
        salt=n,
        person=b'sogs.shared_key',
    ).digest()

    hasher = blake2b(
        method.encode() + full_path.encode() + h['X-SOGS-Timestamp'].encode(),
        digest_size=64,
        key=shared_key,
        salt=n,
        person=b'sogs.request',
    )
    if body is not None and len(body):
        hasher.update(body)
    hsh = hasher.digest()
    h['X-SOGS-Hash'] = sogs.utils.encode_base64(hsh)

    return h, n, ts, hsh


def x_sogs(*args, **kwargs):
    return x_sogs_raw(*args, **kwargs)[0]


@app.get("/auth_test/whoami")
def auth_test_whoami():
    from flask import g, request, jsonify

    res = {}
    if request.query_string:
        res["query"] = request.query_string.decode()
    if g.user is None:
        res["user"] = None
    else:
        res["user"] = {"uid": g.user.id, "session_id": g.user.session_id}

    if request.method == "POST":
        app.logger.warning(f"data is: {request.data}")
        res["body"] = json.loads(request.data) if request.data else None

    return jsonify(res)


@app.get("/auth_test/auth_required")
def auth_test_auth_required():
    from sogs.routes.auth import require_user

    require_user()
    return auth_test_whoami()


@app.post("/auth_test/auth_required")
def auth_test_auth_required_post():
    return auth_test_auth_required()


def test_auth_basic(client, db):
    a = PrivateKey.generate()
    A = a.public_key
    B = server_pubkey

    # Basic auth:
    r = client.get("/auth_test/whoami", headers=x_sogs(a, A, B, 'GET', '/auth_test/whoami'))
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": '05' + A.encode().hex()}}

    # Auth not required, so should be callable without auth:
    r = client.get("/auth_test/whoami")
    assert r.status_code == 200
    assert r.json == {"user": None}

    # Omit b64 padding chars from nonce and hash:
    hh = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    for x in ('Nonce', 'Hash'):
        hdr = 'X-SOGS-' + x
        assert hh[hdr].endswith('=')
        hh[hdr] = hh[hdr].rstrip('=')
        assert not hh[hdr].endswith('=')
    r = client.get("/auth_test/whoami", headers=hh)
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": '05' + A.encode().hex()}}

    # Specify nonce in hex:
    r = client.get(
        "/auth_test/whoami", headers=x_sogs(a, A, B, 'GET', '/auth_test/whoami', b64_nonce=False)
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": '05' + A.encode().hex()}}

    # Barely good timestamp
    r = client.get(
        "/auth_test/whoami",
        headers=x_sogs(a, A, B, 'GET', '/auth_test/whoami', timestamp_off=86399),
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": '05' + A.encode().hex()}}

    r = client.get(
        "/auth_test/whoami",
        headers=x_sogs(a, A, B, 'GET', '/auth_test/whoami', timestamp_off=-86399),
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": '05' + A.encode().hex()}}


def test_auth_required(client, db):
    a = PrivateKey.generate()
    A = a.public_key
    B = server_pubkey

    # Basic auth to auth-required endpoint:
    r = client.get(
        "/auth_test/auth_required", headers=x_sogs(a, A, B, 'GET', '/auth_test/auth_required')
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": '05' + A.encode().hex()}}

    # No auth to required endpoint should fail:
    r = client.get("/auth_test/auth_required")
    assert r.status_code == 401
    assert r.data == b'X-SOGS-* request authentication required'

    # Same no auth, but for a POST request
    r = client.post("/auth_test/auth_required")
    assert r.status_code == 401
    assert r.data == b'X-SOGS-* request authentication required'

    # POST request to a auth-required endpoint, with body and proper auth:
    body = b'[{"hello":     "world"}, 42, null]'
    r = client.post(
        "/auth_test/auth_required",
        data=body,
        content_type='application/json',
        headers=x_sogs(a, A, B, 'POST', '/auth_test/auth_required', body),
    )
    assert r.status_code == 200
    assert r.json == {
        "user": {"uid": 1, "session_id": '05' + A.encode().hex()},
        "body": [{"hello": "world"}, 42, None],
    }


def test_auth_malformed(client, db):
    a = PrivateKey.generate()
    A = a.public_key
    B = server_pubkey

    # Flip a bit in the hash:
    headers, n, ts, hsh = x_sogs_raw(a, A, B, 'GET', '/auth_test/whoami')
    hsh = hsh[0:10] + bytes((hsh[10] ^ 0b100,)) + hsh[11:]
    headers['X-SOGS-Hash'] = sogs.utils.encode_base64(hsh)

    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 401
    assert r.data == b'Invalid authentication: X-SOGS-Hash authentication failed'

    # Missing a header
    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    del headers['X-SOGS-Timestamp']
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication headers: missing 1/4 required X-SOGS-* headers'

    # Empty header
    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Timestamp'] = ''
    headers['X-SOGS-Nonce'] = ''
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication headers: missing 2/4 required X-SOGS-* headers'

    # Wrong path
    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoareu')
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 401
    assert r.data == b'Invalid authentication: X-SOGS-Hash authentication failed'

    # Malformed headers
    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Timestamp'] = headers['X-SOGS-Timestamp'] + 'a'
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication: X-SOGS-Timestamp is not a valid timestamp'

    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = headers['X-SOGS-Nonce'] + '='  # Invalid base64 (too much padding)
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = headers['X-SOGS-Nonce'][:-1]  # Invalid base64 (wrong padding)
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = headers['X-SOGS-Nonce'][:-6]  # chop off 2 padding + last 4 chars
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = sogs.utils.decode_base64(headers['X-SOGS-Nonce']).hex()[:-1]
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = sogs.utils.decode_base64(headers['X-SOGS-Nonce']).hex()[:-2]
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = sogs.utils.decode_base64(headers['X-SOGS-Nonce']).hex() + 'ff'
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    # Attempt to re-use a nonce
    headers = x_sogs(a, A, B, 'GET', '/auth_test/whoami')

    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": '05' + A.encode().hex()}}

    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 425
    assert r.data == b'Invalid authentication: X-SOGS-Nonce cannot be reused'

    # Bad timestamps
    r = client.get(
        "/auth_test/whoami",
        headers=x_sogs(a, A, B, 'GET', '/auth_test/whoami', timestamp_off=86401),
    )
    assert r.status_code == 425
    assert r.data == b'Invalid authentication: X-SOGS-Timestamp is too far from current time'

    r = client.get(
        "/auth_test/whoami",
        headers=x_sogs(a, A, B, 'GET', '/auth_test/whoami', timestamp_off=-86401),
    )
    assert r.status_code == 425
    assert r.data == b'Invalid authentication: X-SOGS-Timestamp is too far from current time'


def test_auth_batch(client, db):
    a = PrivateKey.generate()
    A = a.public_key
    B = server_pubkey

    hi = b'["hi", "world"]'
    reqs = [
        {"method": "GET", "path": "/auth_test/whoami"},
        {"method": "GET", "path": "/auth_test/whoami"},
        {"method": "GET", "path": "/auth_test/whoami"},
        {"method": "GET", "path": "/auth_test/auth_required"},
        {"method": "POST", "path": "/auth_test/auth_required", "b64": sogs.utils.encode_base64(hi)},
        {
            "method": "POST",
            "path": "/auth_test/auth_required",
            "json": {"it's": "you", "main screen": ["turn", "on"]},
        },
    ]

    expected = [
        {
            'code': 200,
            'content-type': 'application/json',
            'body': {'user': {'uid': 1, 'session_id': '05' + A.encode().hex()}},
        },
        {
            'code': 200,
            'content-type': 'application/json',
            'body': {'user': {'uid': 1, 'session_id': '05' + A.encode().hex()}},
        },
        {
            'code': 200,
            'content-type': 'application/json',
            'body': {'user': {'uid': 1, 'session_id': '05' + A.encode().hex()}},
        },
        {
            'code': 200,
            'content-type': 'application/json',
            'body': {'user': {'uid': 1, 'session_id': '05' + A.encode().hex()}},
        },
        {
            'code': 200,
            'content-type': 'application/json',
            'body': {
                'user': {'uid': 1, 'session_id': '05' + A.encode().hex()},
                'body': ['hi', 'world'],
            },
        },
        {
            'code': 200,
            'content-type': 'application/json',
            'body': {
                'user': {'uid': 1, 'session_id': '05' + A.encode().hex()},
                'body': {"it's": "you", "main screen": ["turn", "on"]},
            },
        },
    ]

    # Auth headers go on the outside of the batch request, and should be preserved for the inner
    # requests:
    body = json.dumps(reqs).encode()
    headers = x_sogs(a, A, B, 'POST', '/batch', body)
    r = client.post("/batch", headers=headers, data=body, content_type='application/json')

    assert r.status_code == 200
    assert r.json == expected

    headers = x_sogs(a, A, B, 'POST', '/sequence', body)
    r = client.post("/sequence", headers=headers, data=body, content_type='application/json')

    assert r.status_code == 200
    assert r.json == expected
