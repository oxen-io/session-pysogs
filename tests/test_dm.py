from request import sogs_get, sogs_post, sogs_delete
from sogs import config
from sogs.hashing import blake2b
from sogs.utils import encode_base64
from sogs.model.user import SystemUser
import nacl.bindings as sodium
from nacl.utils import random
from util import from_now
from itertools import product


def test_dm_inbox_nonblinded(client, user):
    r = sogs_get(client, '/inbox', user)
    assert r.status_code == 401


def test_dm_default_empty(client, blind15_user):
    r = sogs_get(client, '/inbox', blind15_user)
    assert r.status_code == 200
    assert r.json == []


def test_dm_banned_user(client, banned_user):
    r = sogs_get(client, '/inbox', banned_user)
    assert r.status_code == 403


def make_post(message, sender, to):
    assert sender.is_blinded
    assert to.is_blinded
    a = sender.ed_key.to_curve25519_private_key().encode()
    kA = bytes.fromhex(sender.using_id[2:])
    kB = bytes.fromhex(to.using_id[2:])
    key = blake2b(sodium.crypto_scalarmult_ed25519_noclamp(a, kB) + kA + kB, digest_size=32)

    # MESSAGE || UNBLINDED_ED_PUBKEY
    plaintext = message + sender.ed_key.verify_key.encode()
    nonce = random(24)
    ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad=None, nonce=nonce, key=key
    )
    data = b'\x00' + ciphertext + nonce
    return {'message': encode_base64(data)}


def test_dm_send_from_banned_user(client, blind15_user, blind15_user2):
    blind15_user2.ban(banned_by=SystemUser())
    r = sogs_post(
        client,
        f'/inbox/{blind15_user.session_id}',
        make_post(b'beep', sender=blind15_user2, to=blind15_user),
        blind15_user2,
    )
    assert r.status_code == 403


def test_dm_send_to_banned_user(client, blind15_user, blind15_user2):
    blind15_user2.ban(banned_by=SystemUser())
    r = sogs_post(
        client,
        f'/inbox/{blind15_user2.session_id}',
        make_post(b'beep', sender=blind15_user, to=blind15_user2),
        blind15_user,
    )
    assert r.status_code == 404


def test_dm_send(client, blind15_user, blind15_user2):
    post = make_post(b'bep', sender=blind15_user, to=blind15_user2)
    msg_expected = {
        'id': 1,
        'message': post['message'],
        'sender': blind15_user.using_id,
        'recipient': blind15_user2.session_id,
    }

    r = sogs_post(client, f'/inbox/{blind15_user2.using_id}', post, blind15_user)
    assert r.status_code == 201
    data = r.json
    assert data.pop('posted_at') == from_now.seconds(0)
    assert data.pop('expires_at') == from_now.seconds(config.DM_EXPIRY)
    assert data == {k: v for k, v in msg_expected.items() if k != 'message'}

    r = sogs_get(client, '/inbox', blind15_user2)
    assert r.status_code == 200
    assert len(r.json) == 1
    data = r.json[0]
    assert data.pop('posted_at') == from_now.seconds(0)
    assert data.pop('expires_at') == from_now.seconds(config.DM_EXPIRY)
    assert data == msg_expected

    r = sogs_get(client, '/outbox', blind15_user)
    assert len(r.json) == 1
    data = r.json[0]
    assert data.pop('posted_at') == from_now.seconds(0)
    assert data.pop('expires_at') == from_now.seconds(config.DM_EXPIRY)
    assert data == msg_expected


def test_dm_delete(client, blind15_user, blind15_user2):
    num_posts = 10
    for sender, recip in product((blind15_user, blind15_user2), repeat=2):
        # make DMs
        for n in range(num_posts):
            print(f"from: {sender.using_id}, to: {recip.using_id}")
            post = make_post(f"bep-{n}".encode('ascii'), sender=sender, to=recip)
            r = sogs_post(client, f'/inbox/{recip.session_id}', post, sender)
            assert r.status_code == 201

        # get DMs
        r = sogs_get(client, "/inbox", recip)
        assert r.status_code == 200
        posts = r.json
        assert isinstance(posts, list)
        assert len(posts) == num_posts

        # delete DMs
        r = sogs_delete(client, "/inbox", recip)
        assert r.status_code == 200
        assert r.json == {'deleted': num_posts}

        # make sure it is empty
        r = sogs_get(client, "/inbox", recip)
        assert r.status_code == 200
        posts = r.json
        assert posts == []

        # delete again when nothing is there
        r = sogs_delete(client, "/inbox", recip)
        assert r.status_code == 200
        assert r.json == {'deleted': 0}

        # make sure it is still empty (probably redundant but good to have)
        r = sogs_get(client, "/inbox", recip)
        assert r.status_code == 200
        posts = r.json
        assert posts == []
