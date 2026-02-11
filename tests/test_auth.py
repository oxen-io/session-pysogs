from sogs.web import app
from sogs.crypto import server_pubkey, compute_blinded25_id_from_05
from sogs.routes.auth import user_required
from auth import x_sogs_raw, x_sogs
import sogs.utils

import json
from nacl.signing import SigningKey
import nacl.bindings as sodium


@app.get("/auth_test/whoami")
def auth_test_whoami():
    from flask import g, request, jsonify

    res = {}
    if request.query_string:
        res["query"] = request.query_string.decode()
    if g.user is None:
        res["user"] = None
    else:
        res["user"] = {"uid": g.user.id, "session_id": g.user.using_id}

    if 'X-Foo' in request.headers:
        res["foo"] = request.headers['X-Foo']

    if request.method == "POST":
        app.logger.warning(f"data is: {request.data}")
        res["body"] = json.loads(request.data) if request.data else None

    return jsonify(res)


@app.get("/auth_test/auth_required")
@user_required
def auth_test_auth_required():
    return auth_test_whoami()


@app.post("/auth_test/auth_required")
def auth_test_auth_required_post():
    return auth_test_auth_required()


def test_auth_basic(client, db):
    a = SigningKey.generate()
    B = server_pubkey
    session_id = '05' + a.verify_key.to_curve25519_public_key().encode().hex()

    # Basic auth:
    print(x_sogs(a, B, 'GET', '/auth_test/whoami'))
    r = client.get("/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami'))
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": session_id}}

    # Auth not required, so should be callable without auth:
    r = client.get("/auth_test/whoami")
    assert r.status_code == 200
    assert r.json == {"user": None}

    # Omit b64 padding chars from nonce:
    hh = x_sogs(a, B, 'GET', '/auth_test/whoami')
    assert hh['X-SOGS-Nonce'].endswith('=')
    hh['X-SOGS-Nonce'] = hh['X-SOGS-Nonce'].rstrip('=')
    assert not hh['X-SOGS-Nonce'].endswith('=')
    r = client.get("/auth_test/whoami", headers=hh)
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": session_id}}

    # Specify nonce in hex:
    r = client.get(
        "/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami', b64_nonce=False)
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": session_id}}

    # Barely good timestamp
    r = client.get(
        "/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami', timestamp_off=86399)
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": session_id}}

    r = client.get(
        "/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami', timestamp_off=-86399)
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": session_id}}


def test_auth_required(client, db):
    a = SigningKey.generate()
    session_id = '05' + a.verify_key.to_curve25519_public_key().encode().hex()
    B = server_pubkey

    # Basic auth to auth-required endpoint:
    r = client.get(
        "/auth_test/auth_required", headers=x_sogs(a, B, 'GET', '/auth_test/auth_required')
    )
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": session_id}}

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
        headers=x_sogs(a, B, 'POST', '/auth_test/auth_required', body),
    )
    assert r.status_code == 200
    assert r.json == {
        "user": {"uid": 1, "session_id": session_id},
        "body": [{"hello": "world"}, 42, None],
    }


def test_auth_banned(client, global_admin, user, db):
    a = user.ed_key
    B = server_pubkey

    r = client.get("/auth_test/whoami")
    assert r.status_code == 200
    assert r.json == {'user': None}
    r = client.get("/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami'))
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 2, "session_id": user.using_id}}

    user.ban(banned_by=global_admin)

    r = client.get("/auth_test/whoami")
    assert r.status_code == 200
    assert r.json == {'user': None}
    r = client.get("/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami'))
    assert r.status_code == 403
    assert r.data == b'Banned'
    r = client.get(
        '/auth_test/auth_required', headers=x_sogs(a, B, 'GET', '/auth_test/auth_required')
    )
    assert r.status_code == 403
    assert r.data == b'Banned'
    r = client.post(
        '/auth_test/auth_required',
        data=b'[1,2,3]',
        headers=x_sogs(a, B, 'POST', '/auth_test/auth_required', b'[1,2,3]'),
    )
    assert r.status_code == 403
    assert r.data == b'Banned'


def test_auth_malformed(client, db):
    a = SigningKey.generate()
    session_id = '05' + a.verify_key.to_curve25519_public_key().encode().hex()
    B = server_pubkey

    # Flip a bit in the hash:
    headers, n, ts, sig = x_sogs_raw(a, B, 'GET', '/auth_test/whoami')
    sig = sig[0:10] + bytes((sig[10] ^ 0b100,)) + sig[11:]
    headers['X-SOGS-Signature'] = sogs.utils.encode_base64(sig)

    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 401
    assert r.data == b'Invalid authentication: X-SOGS-Signature verification failed'

    # Wrong hash size:
    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Signature'] = headers['X-SOGS-Signature'][:-4]
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication: X-SOGS-Signature is not base64[88]'

    # Missing a header
    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    del headers['X-SOGS-Timestamp']
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication headers: missing 1/4 required X-SOGS-* headers'

    # Empty header
    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Timestamp'] = ''
    headers['X-SOGS-Nonce'] = ''
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication headers: missing 2/4 required X-SOGS-* headers'

    # Wrong path
    headers = x_sogs(a, B, 'GET', '/auth_test/whoareu')
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 401
    assert r.data == b'Invalid authentication: X-SOGS-Signature verification failed'

    # Malformed headers
    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Timestamp'] = headers['X-SOGS-Timestamp'] + 'a'
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication: X-SOGS-Timestamp is not a valid timestamp'

    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = headers['X-SOGS-Nonce'] + '='  # Invalid base64 (too much padding)
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = headers['X-SOGS-Nonce'][:-1]  # Invalid base64 (wrong padding)
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = headers['X-SOGS-Nonce'][:-6]  # chop off 2 padding + last 4 chars
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = sogs.utils.decode_base64(headers['X-SOGS-Nonce']).hex()[:-1]
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = sogs.utils.decode_base64(headers['X-SOGS-Nonce']).hex()[:-2]
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')
    headers['X-SOGS-Nonce'] = sogs.utils.decode_base64(headers['X-SOGS-Nonce']).hex() + 'ff'
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert (
        r.data
        == b'Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)'
    )

    # Attempt to re-use a nonce
    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')

    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 200
    assert r.json == {"user": {"uid": 1, "session_id": session_id}}

    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 425
    assert r.data == b'Invalid authentication: X-SOGS-Nonce cannot be reused'

    # Bad timestamps
    r = client.get(
        "/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami', timestamp_off=86402)
    )
    assert r.status_code == 425
    assert r.data == b'Invalid authentication: X-SOGS-Timestamp is too far from current time'

    r = client.get(
        "/auth_test/whoami", headers=x_sogs(a, B, 'GET', '/auth_test/whoami', timestamp_off=-86402)
    )
    assert r.status_code == 425
    assert r.data == b'Invalid authentication: X-SOGS-Timestamp is too far from current time'


def test_auth_batch(client, db):
    a = SigningKey.generate()
    session_id = '05' + a.verify_key.to_curve25519_public_key().encode().hex()
    B = server_pubkey

    hi = b'["hi", "world"]'
    reqs = [
        {"method": "GET", "path": "/auth_test/whoami", "headers": {"X-Foo": "bar"}},
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
            'headers': {'content-type': 'application/json'},
            'body': {'user': {'uid': 1, 'session_id': session_id}, 'foo': 'bar'},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'user': {'uid': 1, 'session_id': session_id}},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'user': {'uid': 1, 'session_id': session_id}},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'user': {'uid': 1, 'session_id': session_id}},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'user': {'uid': 1, 'session_id': session_id}, 'body': ['hi', 'world']},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {
                'user': {'uid': 1, 'session_id': session_id},
                'body': {"it's": "you", "main screen": ["turn", "on"]},
            },
        },
    ]

    # Auth headers go on the outside of the batch request, and should be preserved for the inner
    # requests:
    body = json.dumps(reqs).encode()
    headers = x_sogs(a, B, 'POST', '/batch', body)
    r = client.post("/batch", headers=headers, data=body, content_type='application/json')

    assert r.status_code == 200
    assert r.json == expected

    headers = x_sogs(a, B, 'POST', '/sequence', body)
    r = client.post("/sequence", headers=headers, data=body, content_type='application/json')

    assert r.status_code == 200
    assert r.json == expected

    # Auth headers on the *inner* batch requests should be ignored:
    a2 = SigningKey.generate()
    inner_h1 = x_sogs(a2, B, 'GET', '/auth_test/whoami')
    inner_h1['X-Foo'] = 'bar'
    inner_h2 = x_sogs(a2, B, 'POST', '/auth_test/auth_required', hi)
    reqs = [
        {"method": "GET", "path": "/auth_test/whoami", "headers": inner_h1},
        {"method": "GET", "path": "/auth_test/whoami"},
        {
            "method": "POST",
            "path": "/auth_test/auth_required",
            "headers": inner_h2,
            "b64": sogs.utils.encode_base64(hi),
        },
    ]
    body = json.dumps(reqs).encode()
    headers = x_sogs(a, B, 'POST', '/batch', body)
    r = client.post("/batch", headers=headers, data=body, content_type='application/json')
    assert r.status_code == 200
    assert r.json == [expected[i] for i in (0, 1, 4)]


def test_auth_legacy(client, db, admin, user, room):
    # Make a legacy auth token to make sure it works as expected first, but also to make sure it
    # gets ignored when we use X-SOGS-*.
    raw_token = sogs.utils.make_legacy_token(admin.using_id)
    token = sogs.utils.encode_base64(raw_token)

    a = admin.ed_key
    B = server_pubkey

    a2 = SigningKey.generate()

    # Test that invalid token with legacy auth is recognized:
    bad_token = sogs.utils.encode_base64(bytes((raw_token[0] ^ 1,)) + raw_token[1:])
    r = client.post(
        "/legacy/block_list",
        headers={"Room": room.token, "Authorization": bad_token},
        json={"public_key": user.using_id},
    )
    assert r.status_code == 401

    # Add a couple of bans:
    r = client.post(
        "/legacy/block_list",
        headers={"Room": room.token, "Authorization": token},
        json={"public_key": user.using_id},
    )
    assert r.status_code == 200
    assert r.json == {"status_code": 200}

    S2 = '05' + a2.verify_key.to_curve25519_public_key().encode().hex()
    S2_25 = compute_blinded25_id_from_05(S2)
    r = client.post(
        "/legacy/block_list",
        headers={"Room": room.token, "Authorization": token},
        json={"public_key": S2},
    )
    assert r.status_code == 200
    assert r.json == {"status_code": 200}

    # Verify that both bans are present
    r = client.get("/legacy/block_list", headers={"Room": room.token, "Authorization": token})
    assert r.status_code == 200
    assert r.json == {"status_code": 200, "banned_members": sorted([user.session_id, S2_25])}

    # Retrieve bans as one of the banned users: should only see himself
    utoken = sogs.utils.encode_base64(sogs.utils.make_legacy_token(user.using_id))
    r = client.get("/legacy/block_list", headers={"Room": room.token, "Authorization": utoken})
    assert r.status_code == 200
    assert r.json == {"status_code": 200, "banned_members": [user.session_id]}

    # Same, but now use X-SOGS-*
    h = x_sogs(user.ed_key, B, 'GET', '/legacy/block_list')
    h['Room'] = room.token
    r = client.get("/legacy/block_list", headers=h)
    assert r.status_code == 200
    assert r.json == {"status_code": 200, "banned_members": [user.session_id]}

    # Now use X-SOGS-* for the second user, but pass an Authentication header for the first user
    # (which should be ignored with X-SOGS-* headers present).
    h = x_sogs(a2, B, 'GET', '/legacy/block_list')
    h['Room'] = room.token
    r = client.get("/legacy/block_list", headers=h)
    assert r.status_code == 200
    assert r.json == {"status_code": 200, "banned_members": [S2_25]}

    app.logger.warning(f"spacing log line")

    # Remove the bans as admin, with X-SOGS
    rh = {"Room": room.token}
    body = json.dumps(
        [
            {'method': 'GET', 'path': '/legacy/block_list', "headers": rh},
            {'method': 'DELETE', 'path': '/legacy/block_list/' + user.session_id, "headers": rh},
            {'method': 'GET', 'path': '/legacy/block_list', "headers": rh},
            {
                'method': 'DELETE',
                'path': '/legacy/block_list/' + S2,
                # non-admin inner auth token, but should get ignored:
                "headers": {**rh, 'Authorization': utoken},
            },
            {'method': 'GET', 'path': '/legacy/block_list', "headers": rh},
        ]
    ).encode()
    r = client.post(
        "/sequence",
        data=body,
        content_type='application/json',
        headers=x_sogs(a, B, 'POST', '/sequence', body),
    )
    assert r.status_code == 200
    assert r.json == [
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'status_code': 200, 'banned_members': sorted([user.session_id, S2_25])},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'status_code': 200},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'status_code': 200, 'banned_members': [S2_25]},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'status_code': 200},
        },
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'status_code': 200, 'banned_members': []},
        },
    ]


def test_small_subgroups(client, db):
    # Make some public keys with small subgroup components to make sure sodium rejects them (it
    # does, everythwere that matters here).
    a = SigningKey.generate()
    B = server_pubkey
    headers = x_sogs(a, B, 'GET', '/auth_test/whoami')

    assert headers['X-SOGS-Pubkey'].startswith('00')
    A = bytes.fromhex(headers['X-SOGS-Pubkey'][2:])

    assert A == a.verify_key.encode()

    if hasattr(sodium, 'crypto_core_ed25519_is_valid_point'):
        assert sodium.crypto_core_ed25519_is_valid_point(A)

    Abad = sodium.crypto_core_ed25519_add(
        A, bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    )

    if hasattr(sodium, 'crypto_core_ed25519_is_valid_point'):
        assert not sodium.crypto_core_ed25519_is_valid_point(Abad)

    headers['X-SOGS-Pubkey'] = '00' + Abad.hex()

    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication: given X-SOGS-Pubkey is not a valid Ed25519 pubkey'

    # Now try with a blinded id:
    headers = x_sogs(a, B, 'GET', '/auth_test/whoami', blinded15=True)
    assert headers['X-SOGS-Pubkey'].startswith('15')
    A = bytes.fromhex(headers['X-SOGS-Pubkey'][2:])

    Abad = sodium.crypto_core_ed25519_add(
        A, bytes.fromhex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a')
    )

    if hasattr(sodium, 'crypto_core_ed25519_is_valid_point'):
        assert not sodium.crypto_core_ed25519_is_valid_point(Abad)

    headers['X-SOGS-Pubkey'] = '15' + Abad.hex()
    r = client.get("/auth_test/whoami", headers=headers)
    assert r.status_code == 400
    assert r.data == b'Invalid authentication: given X-SOGS-Pubkey is not a valid Ed25519 pubkey'
