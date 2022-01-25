from nacl.public import PublicKey, PrivateKey
from typing import Optional
import time
from hashlib import blake2b
from nacl.bindings import crypto_scalarmult
from nacl.utils import random

import sogs.utils
import sogs.crypto


def x_sogs_nonce():
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
    n = x_sogs_nonce()
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
        digest_size=42,
        salt=n,
        person=b'sogs.shared_keys',
    ).digest()

    hasher = blake2b(
        method.encode() + full_path.encode() + h['X-SOGS-Timestamp'].encode(),
        digest_size=42,
        key=shared_key,
        salt=n,
        person=b'sogs.auth_header',
    )
    if body is not None and len(body):
        hasher.update(body)
    hsh = hasher.digest()
    h['X-SOGS-Hash'] = sogs.utils.encode_base64(hsh)

    return h, n, ts, hsh


def x_sogs(*args, **kwargs):
    return x_sogs_raw(*args, **kwargs)[0]


def x_sogs_for(user, *args, **kwargs):
    a = user.privkey
    A = a.public_key
    B = sogs.crypto.server_pubkey
    return x_sogs(a, A, B, *args, **kwargs)
