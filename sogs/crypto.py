from . import config

import os

import nacl
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder, HexEncoder
from nacl.bindings import crypto_scalarmult


from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .utils import decode_hex_or_b64
from .hashing import blake2b

import binascii
import secrets
import hmac
import functools

import pyonionreq

if [int(v) for v in nacl.__version__.split('.')] < [1, 4]:
    raise ImportError("SOGS requires nacl v1.4.0+")


def persist_privkey():
    """
    Writes the current private key to disk if it is ephemeral.  This is done automatically when a
    private key is generated in uwsgi application mode; for other interfaces it needs to be called
    manually if the key should be persisted.

    If the key was loaded from disk originally then this does nothing.
    """
    global ephemeral_privkey
    if ephemeral_privkey:
        with open(os.open(config.KEY_FILE, os.O_CREAT | os.O_WRONLY, 0o400), 'wb') as f:
            f.write(_privkey.encode())
        ephemeral_privkey = False


ephemeral_privkey = True

# generate seed as needed
if os.path.exists(config.KEY_FILE):
    with open(config.KEY_FILE, 'rb') as f:
        _privkey = PrivateKey(f.read())
    ephemeral_privkey = False
else:
    _privkey = PrivateKey.generate()

    # Only save the key if we're running under uswgi to avoid leaving key_ed25519 files all over the
    # place wherever sogs is imported.
    if config.RUNNING_AS_APP:
        persist_privkey()

_privkey_bytes = _privkey.encode()

server_pubkey = _privkey.public_key

server_pubkey_bytes = server_pubkey.encode()
server_pubkey_hash_bytes = blake2b(server_pubkey_bytes)

server_pubkey_hex = server_pubkey.encode(HexEncoder).decode('ascii')
server_pubkey_base64 = server_pubkey.encode(Base64Encoder).decode('ascii')

_junk_parser = pyonionreq.junk.Parser(privkey=_privkey_bytes, pubkey=server_pubkey_bytes)
parse_junk = _junk_parser.parse_junk


def verify_sig_from_pk(data, sig, pk):
    return VerifyKey(pk).verify(data, sig)


_server_signkey = SigningKey(_privkey_bytes)

server_verify = _server_signkey.verify_key.verify

server_sign = _server_signkey.sign


def server_encrypt(pk, data):
    nonce = secrets.token_bytes(12)
    pk = X25519PublicKey.from_public_bytes(pk)
    sk = X25519PrivateKey.from_private_bytes(_privkey_bytes)
    secret = hmac.digest(b'LOKI', sk.exchange(pk), 'SHA256')
    return nonce + AESGCM(secret).encrypt(nonce, data, None)


xed25519_sign = pyonionreq.xed25519.sign
xed25519_verify = pyonionreq.xed25519.verify
xed25519_pubkey = pyonionreq.xed25519.pubkey


@functools.lru_cache(maxsize=1024)
def compute_derived_key_bytes(pk_bytes):
    """compute derived key as bytes with no prefix"""
    return crypto_scalarmult(server_pubkey_hash_bytes, pk_bytes)


def compute_derived_id(session_id, prefix='15'):
    """compute derived session"""
    return prefix + binascii.hexlify(
        compute_derived_key_bytes(decode_hex_or_b64(session_id[2:], 32))
    ).decode('ascii')
