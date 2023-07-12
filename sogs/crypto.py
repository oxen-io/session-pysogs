from . import config

import os

import nacl
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder, HexEncoder
import nacl.bindings as sodium


from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .hashing import blake2b

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


server_signkey = SigningKey(_privkey_bytes)
server_verifykey = server_signkey.verify_key

server_verify = server_verifykey.verify
server_sign = server_signkey.sign


def server_encrypt(pk, data):
    nonce = secrets.token_bytes(12)
    pk = X25519PublicKey.from_public_bytes(pk)
    sk = X25519PrivateKey.from_private_bytes(_privkey_bytes)
    secret = hmac.digest(b'LOKI', sk.exchange(pk), 'SHA256')
    return nonce + AESGCM(secret).encrypt(nonce, data, None)


xed25519_sign = pyonionreq.xed25519.sign
xed25519_verify = pyonionreq.xed25519.verify
xed25519_pubkey = pyonionreq.xed25519.pubkey

# AKA "k" for blinding crypto:
blinding_factor = sodium.crypto_core_ed25519_scalar_reduce(
    blake2b(server_pubkey_bytes, digest_size=64)
)


@functools.lru_cache(maxsize=1024)
def compute_blinded15_abs_key(x_pk: bytes, *, k: bytes = blinding_factor):
    """
    Computes the *positive* blinded Ed25519 pubkey from an unprefixed session X25519 pubkey (i.e. 32
    bytes).  The returned value will always have the sign bit (i.e. the most significant bit of the
    last byte) set to 0; the actual derived key associated with this session id could have either
    sign.

    Input and result are in bytes, without the 0x05 or 0x15 prefix.

    k allows you to compute for an alternative blinding factor, but should normally be omitted.
    """
    A = xed25519_pubkey(x_pk)
    kA = sodium.crypto_scalarmult_ed25519_noclamp(k, A)

    if kA[31] & 0x80:
        return kA[0:31] + bytes([kA[31] & 0x7F])
    return kA


def compute_blinded15_abs_id(session_id: str, *, k: bytes = blinding_factor):
    """
    Computes the *positive* blinded id, as hex, from a prefixed, hex session id.  This function is a
    wrapper around compute_derived_key_bytes that handles prefixes and hex conversions.

    k allows you to compute for an alternative blinding factor, but should normally be omitted.
    """
    return '15' + compute_blinded15_abs_key(bytes.fromhex(session_id[2:]), k=k).hex()


def blinded_abs(blinded_id: str):
    """
    Takes a blinded hex pubkey (i.e. length 66, prefixed with 15) and returns the positive pubkey
    alternative: that is, if the pubkey is already positive, it is returned as-is; otherwise the
    returned value is a copy with the sign bit cleared.
    """

    # Sign bit is the MSB of the last byte, which will be at [31] of the private key, hence 64 is
    # the most significant nibble once we convert to hex and add 2 for the prefix:
    msn = int(blinded_id[64], 16)
    if msn & 0x8:
        return blinded_id[0:64] + str(msn & 0x7) + blinded_id[65:]
    return blinded_id


def blinded_neg(blinded_id: str):
    """
    Counterpart to blinded_abs that always returns the *negative* pubkey alternative.
    """

    msn = int(blinded_id[64], 16)
    if msn & 0x8:
        return blinded_id
    return blinded_id[0:64] + f"{msn | 0x8:x}" + blinded_id[65:]
