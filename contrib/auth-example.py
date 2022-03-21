# Example script for demonstrating X-SOGS-* authentication calculation.

import nacl.bindings as sodium
from nacl.signing import SigningKey
from hashlib import blake2b, sha512
from base64 import b64encode

# import time
# import nacl.utils


def sha512_multipart(*message_parts):
    """Given any number of arguments, returns the SHA512 hash of them concatenated together.  This
    also does one level of flatting if any of the given parts are a list or tuple."""
    hasher = sha512()
    for m in message_parts:
        if isinstance(m, list) or isinstance(m, tuple):
            for mi in m:
                hasher.update(mi)
        else:
            hasher.update(m)
    return hasher.digest()


def blinded_ed25519_signature(message_parts, s: SigningKey, ka: bytes, kA: bytes):
    """
    Constructs an Ed25519 signature from a root Ed25519 key and a blinded scalar/pubkey pair, with
    one tweak to the construction: we add kA into the hashed value that yields r so that we have
    domain separation for different blinded pubkeys.  (This doesn't affect verification at all).
    """
    H_rh = sha512(s.encode()).digest()[32:]
    r = sodium.crypto_core_ed25519_scalar_reduce(sha512_multipart(H_rh, kA, message_parts))
    sig_R = sodium.crypto_scalarmult_ed25519_base_noclamp(r)
    HRAM = sodium.crypto_core_ed25519_scalar_reduce(sha512_multipart(sig_R, kA, message_parts))
    sig_s = sodium.crypto_core_ed25519_scalar_add(
        r, sodium.crypto_core_ed25519_scalar_mul(HRAM, ka)
    )
    return sig_R + sig_s


def get_signing_headers(
    s: SigningKey,
    server_pk: bytes,
    nonce: bytes,
    method: str,
    path: str,
    timestamp: int,
    body,
    blinded: bool = True,
):

    assert len(server_pk) == 32
    assert len(nonce) == 16

    if blinded:
        # 64-byte blake2b hash then reduce to get the blinding factor:
        k = sodium.crypto_core_ed25519_scalar_reduce(blake2b(server_pk, digest_size=64).digest())

        # Calculate k*a.  To get 'a' (the Ed25519 private key scalar) we call the sodium function to
        # convert to an *x* secret key, which seems wrong--but isn't because converted keys use the
        # same secret scalar secret.  (And so this is just the most convenient way to get 'a' out of
        # a sodium Ed25519 secret key).
        a = s.to_curve25519_private_key().encode()

        # Our blinded keypair:
        ka = sodium.crypto_core_ed25519_scalar_mul(k, a)
        kA = sodium.crypto_scalarmult_ed25519_base_noclamp(ka)

        # Blinded session id:
        pubkey = '15' + kA.hex()

    else:
        # For unblinded auth we send our *ed25519* master pubkey in the X-SOGS-Pubkey header with a
        # '00' prefix to disambiguate it; the SOGS server will convert it to X25519 to derive our
        # X25519 session id.
        pubkey = '00' + s.verify_key.encode().hex()

    # We need to sign:
    # SERVER_PUBKEY || NONCE || TIMESTAMP || METHOD || PATH || HBODY
    # with our blinded key (if blinding) or our Ed25519 master key (if not blinding).
    to_sign = [server_pk, nonce, str(ts).encode(), method.encode(), path.encode()]

    # HBODY may be omitted if the body is empty (e.g. for GET requests), and otherwise will be the
    # 64-byte BLAKE2b hash of the request body:
    if body is not None:
        to_sign.append(blake2b(body, digest_size=64).digest())

    if blinded:
        sig = blinded_ed25519_signature(to_sign, s, ka, kA)
    else:
        sig = s.sign(b''.join(to_sign)).signature

    return {
        'X-SOGS-Pubkey': pubkey,
        'X-SOGS-Timestamp': str(ts),
        'X-SOGS-Nonce': b64encode(nonce).decode(),
        'X-SOGS-Signature': b64encode(sig).decode(),
    }


# Session "master" ed25519 key:
s = SigningKey(bytes.fromhex('c010d89eccbaf5d1c6d19df766c6eedf965d4a28a56f87c9fc819edb59896dd9'))
# Server pubkey:
B = bytes.fromhex('c3b3c6f32f0ab5a57f853cc4f30f5da7fda5624b0c77b3fb0829de562ada081d')
# Random 16-byte nonce
# nonce = nacl.utils.random(16)
nonce = bytes.fromhex('09d0799f2295990182c3ab3406fbfc5b')  # fixed for reproducible example
# ts = int(time.time())
ts = 1642472103  # for reproducible example
method, path = 'GET', '/room/the-best-room/messages/recent?limit=25'

print("Unblinded headers:")
sig_headers = get_signing_headers(s, B, nonce, method, path, ts, body=None, blinded=False)
for h, v in sig_headers.items():
    print(f"{h}: {v}")

print("\nBlinded headers:")
sig_headers = get_signing_headers(s, B, nonce, method, path, ts, body=None, blinded=True)
for h, v in sig_headers.items():
    print(f"{h}: {v}")


# Prints:
# Unblinded headers:
# X-SOGS-Pubkey: 00bac6e71efd7dfa4a83c98ed24f254ab2c267f9ccdb172a5280a0444ad24e89cc
# X-SOGS-Timestamp: 1642472103
# X-SOGS-Nonce: CdB5nyKVmQGCw6s0Bvv8Ww==
# X-SOGS-Signature: xxLpXHbomAJMB9AtGMyqvBsXrdd2040y+Ol/IKzElWfKJa3EYZRv1GLO6CTLhrDFUwVQe8PPltyGs54Kd7O5Cg==   # noqa E501
#
# Blinded headers:
# X-SOGS-Pubkey: 1598932d4bccbe595a8789d7eb1629cefc483a0eaddc7e20e8fe5c771efafd9af5
# X-SOGS-Timestamp: 1642472103
# X-SOGS-Nonce: CdB5nyKVmQGCw6s0Bvv8Ww==
# X-SOGS-Signature: gYqpWZX6fnF4Gb2xQM3xaXs0WIYEI49+B8q4mUUEg8Rw0ObaHUWfoWjMHMArAtP9QlORfiydsKWz1o6zdPVeCQ==  # noqa E501
