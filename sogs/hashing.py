import nacl.hashlib
import hashlib


def _multipart_hash(hasher, data):
    if isinstance(data, bytes):
        hasher.update(data)
    else:
        for part in data:
            hasher.update(part)

    return hasher.digest()


def blake2b(
    data, *, digest_size: int = 32, key: bytes = b'', salt: bytes = b'', person: bytes = b''
):
    """
    Calculates a Blake2B hash.

    Parameters:

    data -- can be bytes, or an iterable containing bytes or byte-like values.  (The latter case is
    particularly recommended to avoid needing to concatenate existing, potentially large, byte
    values).

    digest_size -- the digest size, in bytes, which affects both the resulting length but also the
    hash itself (i.e.  shorter digest sizes are not substrings of longer hash sizes).

    key -- a key, for a keyed hash, which can be up to 64 bytes.

    salt -- a salt for generating distinct hashes for the same data.  Can be up to 16 bytes; if
    shorter than 16 it will be padded with null bytes.

    person -- a personalization value, which works essentially like a second salt but is typically a
    unique fixed string for a particular hash purpose.

    Returns a bytes of length `digest_size`.
    """

    return _multipart_hash(
            nacl.hashlib.blake2b(digest_size=digest_size, key=key, salt=salt, person=person),
            data)


def sha512(data):
    """
    Calculates a SHA512 hash.

    data -- can be bytes, or an iterable containing bytes or byte-like values.  (The latter case is
    particularly recommended to avoid needing to concatenate existing, potentially large, byte
    values).

    Returns a bytes of length 64.
    """
    return _multipart_hash(
            hashlib.sha512(),
            data)
