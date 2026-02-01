from nacl.signing import SigningKey
from nacl.public import PublicKey
from typing import Optional
import time
from sogs.hashing import blake2b, sha512
import nacl.bindings as sodium
from nacl.utils import random
import urllib.parse

import sogs.utils
import sogs.crypto


def x_sogs_nonce():
    return random(16)


def x_sogs_raw(
    s: SigningKey,
    B: PublicKey,
    method: str,
    full_path: str,
    body: Optional[bytes] = None,
    *,
    b64_nonce: bool = True,
    blinded15: bool = False,
    blinded25: bool = False,
    timestamp_off: int = 0,
    nonce: bytes = None,
):
    """
    Calculates X-SOGS-* headers.

    Returns 4 elements: the headers dict, the nonce bytes, timestamp int, and signature bytes.

    Use x_sogs(...) instead if you don't need the nonce/timestamp/signature values.
    """
    n = nonce if nonce else x_sogs_nonce()
    ts = int(time.time()) + timestamp_off

    if blinded25:
        blind25_keypair = blinding.blind25_key_pair(s.encode(), sogs.crypto.server_pubkey_bytes)
        kA = blind25_keypair.pubkey
        ka = blind25_keypair.privkey
        pubkey = '25' + kA.hex()
    elif blinded15:
        a = s.to_curve25519_private_key().encode()
        k = sodium.crypto_core_ed25519_scalar_reduce(
            blake2b(sogs.crypto.server_pubkey_bytes, digest_size=64)
        )
        ka = sodium.crypto_core_ed25519_scalar_mul(k, a)
        kA = sodium.crypto_scalarmult_ed25519_base_noclamp(ka)
        pubkey = '15' + kA.hex()
    else:
        pubkey = '00' + s.verify_key.encode().hex()

    if '%' in full_path:
        full_path = urllib.parse.unquote(full_path)

    to_sign = [B.encode(), n, str(ts).encode(), method.encode(), full_path.encode()]
    if body:
        to_sign.append(blake2b(body, digest_size=64))

    if blinded15 or blinded25:
        H_rh = sha512(s.encode())[32:]
        r = sodium.crypto_core_ed25519_scalar_reduce(sha512([H_rh, kA, *to_sign]))
        sig_R = sodium.crypto_scalarmult_ed25519_base_noclamp(r)
        HRAM = sodium.crypto_core_ed25519_scalar_reduce(sha512([sig_R, kA, *to_sign]))
        sig_s = sodium.crypto_core_ed25519_scalar_add(
            r, sodium.crypto_core_ed25519_scalar_mul(HRAM, ka)
        )
        sig = sig_R + sig_s

    else:
        sig = s.sign(b''.join(to_sign)).signature

    h = {
        'X-SOGS-Pubkey': pubkey,
        'X-SOGS-Nonce': sogs.utils.encode_base64(n) if b64_nonce else n.hex(),
        'X-SOGS-Timestamp': str(ts),
        'X-SOGS-Signature': sogs.utils.encode_base64(sig),
    }

    return h, n, ts, sig


def x_sogs(*args, **kwargs):
    return x_sogs_raw(*args, **kwargs)[0]


def x_sogs_for(user, *args, **kwargs):
    B = sogs.crypto.server_pubkey
    return x_sogs(
        user.ed_key, B, *args, blinded15=user.is_blinded15, blinded25=user.is_blinded25, **kwargs
    )
