from request import sogs_get, sogs_post
from sogs import crypto

from base64 import b64encode


def test_dm_default_empty(client, blind_user):
    r = sogs_get(client, '/inbox', blind_user)
    assert r.status_code == 200
    assert r.json == []


def test_dm_banned_user(client, banned_user):
    r = sogs_get(client, '/inbox', banned_user)
    assert r.status_code == 403


def make_post(data, user):
    privkey = crypto.compute_derived_key_bytes(user.privkey.encode())
    sig = crypto.xed25519_sign(privkey, data)
    return {'message': b64encode(data).decode('ascii'), 'signature': b64encode(sig).decode('ascii')}


def test_dm_send_from_bannend_user(client, blind_user, banned_user):
    r = sogs_post(
        client, f'/inbox/{blind_user.session_id}', make_post(b'beep', banned_user), banned_user
    )
    assert r.status_code == 403


def test_dm_send_to_bannend_user(client, blind_user, banned_user):
    r = sogs_post(
        client, f'/inbox/{banned_user.session_id}', make_post(b'beep', blind_user), blind_user
    )
    assert r.status_code == 404


def test_dm_send(client, blind_user, blind_user2):
    post = make_post(b'bep', blind_user)
    r = sogs_post(client, f'/inbox/{blind_user2.session_id}', post, blind_user)
    assert r.status_code == 201
    r = sogs_get(client, '/inbox', blind_user2)
    assert r.status_code == 200
    for entry in r.json:
        if entry['message'] == post['message']:
            break
    else:
        assert False
