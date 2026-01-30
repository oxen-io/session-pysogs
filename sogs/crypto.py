from . import config

import os
from typing import Optional

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

from session_util import blinding, xed25519

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


# AKA "k" for deprecated 15xxx blinding crypto:
blinding15_factor = sodium.crypto_core_ed25519_scalar_reduce(
    blake2b(server_pubkey_bytes, digest_size=64)
)
b15_inv = sodium.crypto_core_ed25519_scalar_invert(blinding15_factor)


@functools.lru_cache(maxsize=1024)
def compute_blinded_abs_key_base(x_pk: bytes, *, k: bytes):
    """
    Computes the *positive* blinded Ed25519 pubkey from an unprefixed session X25519 pubkey (i.e. 32
    bytes) and blinding factor.  The returned value will always have the sign bit (i.e. the most
    significant bit of the last byte) set to 0; the actual derived key associated with this session
    id could have either sign.

    Input and result are raw pubkeys as bytes (i.e. no 0x05/0x15/0x25 prefix).

    k is specific to the type of ublinding in use (e.g. 15xx or 25xx use different k values).
    """
    A = xed25519.pubkey(x_pk)
    kA = sodium.crypto_scalarmult_ed25519_noclamp(k, A)

    if kA[31] & 0x80:
        return kA[0:31] + bytes([kA[31] & 0x7F])
    return kA


def compute_blinded15_abs_key(x_pk: bytes, *, _k: bytes = blinding15_factor):
    """
    Computes the *positive* deprecated 15xxx blinded Ed25519 pubkey from an unprefixed session
    X25519 pubkey (i.e.  32 bytes).

    Input and result are in bytes, without the 0x05 or 0x15 prefix.

    _k is used by the test suite to use an alternate blinding factor and should not normally be
    passed.
    """
    return compute_blinded_abs_key_base(x_pk, k=_k)


def compute_blinded15_abs_id(session_id: str, *, _k: bytes = blinding15_factor):
    """
    Computes the *positive* 15xxx deprecated blinded id, as hex, from a prefixed, hex session id.
    This function is a wrapper around compute_blinded15_abs_key that handles prefixes and hex
    conversions.

    _k is used by the test suite to use an alternate blinding factor and should not normally be
    passed.
    """
    return '15' + compute_blinded15_abs_key(bytes.fromhex(session_id[2:]), _k=_k).hex()


@functools.lru_cache(maxsize=1024)
def compute_blinded25_key_from_15(blinded15_pubkey: bytes, *, _server_pk: Optional[bytes] = None):
    """
    Computes a 25xxx blinded key from a given 15xxx blinded key.  Takes just the pubkey (i.e. not
    including the 0x15) as bytes, returns just the pubkey as bytes (i.e. no 0x25 prefix).

    _server_pk is only for the test suite and should not be passed.
    """
    if _server_pk is None:
        _server_pk = server_pubkey_bytes
        k15_inv = b15_inv
    else:
        k15_inv = sodium.crypto_core_ed25519_scalar_invert(
            sodium.crypto_core_ed25519_scalar_reduce(blake2b(_server_pk, digest_size=64))
        )

    ed = sodium.crypto_scalarmult_ed25519_noclamp(k15_inv, blinded15_pubkey)
    x = sodium.crypto_sign_ed25519_pk_to_curve25519(ed)
    return blinding.blind25_id(x, _server_pk)[1:]


def compute_blinded25_id_from_15(blinded15_id: str, *, _server_pk: Optional[bytes] = None):
    """
    Same as above, but works on and returns prefixed hex strings.
    """
    return (
        '25'
        + compute_blinded25_key_from_15(
            bytes.fromhex(blinded15_id[2:]), _server_pk=_server_pk
        ).hex()
    )


def compute_blinded25_id_from_05(session_id: str, *, _server_pk: Optional[bytes] = None):
    if _server_pk is None:
        _server_pk = server_pubkey_bytes
    return '25' + blinding.blind25_id(bytes.fromhex(session_id[2:]), _server_pk)[1:].hex()


def blinded15_abs(blinded_id: str):
    """
    Takes a 15-blinded hex pubkey (i.e. length 66, prefixed with 15) and returns the positive pubkey
    alternative (including prefix): that is, if the pubkey is already positive, it is returned
    as-is; otherwise the returned value is a copy with the sign bit cleared.
    """

    # Sign bit is the MSB of the last byte, which will be at [31] of the private key, hence 64 is
    # the most significant nibble once we convert to hex and add 2 for the prefix:
    msn = int(blinded_id[64], 16)
    if msn & 0x8:
        return blinded_id[0:64] + str(msn & 0x7) + blinded_id[65:]
    return blinded_id


def blinded15_neg(blinded_id: str):
    """
    Counterpart to blinded15_abs that always returns the *negative* pubkey alternative.
    """

    msn = int(blinded_id[64], 16)
    if msn & 0x8:
        return blinded_id
    return blinded_id[0:64] + f"{msn | 0x8:x}" + blinded_id[65:]
