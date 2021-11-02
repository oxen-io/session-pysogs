import base64

from . import crypto
from . import config


encode_base64 = base64.b64encode


def decode_base64(b64: str):
    """Decodes a base64 value with or without padding."""
    # Accept unpadded base64 by appending padding; b64decode won't accept it otherwise
    if 2 <= len(b64) % 4 <= 3 and not b64.endswith('='):
        b64 += '=' * (4 - len(b64) % 4)
    return base64.b64decode(b64, validate=True)


def decode_hex_or_b64(data: bytes, size: int):
    """
    Decodes hex or base64-encoded input of a binary value of size `size`.  Returns None if data is
    None; otherwise the bytes value, if parsing is successful.  Throws on invalid data.

    (Size is required because many hex strings are valid base64 and vice versa.)
    """
    if data is None:
        return None

    if len(data) == size*2:
        return bytes.fromhex(data)

    b64_size = (size + 2) // 3 * 4 # bytes*4/3, rounded up to the next multiple of 4.
    b64_unpadded = (size * 4 + 2) // 3

    # Allow unpadded data; python's base64 has no ability to load an unpadded value, though, so pad
    # it ourselves:
    if b64_unpadded <= len(data) <= b64_size:
        decoded = base64.b64decode(data)
        if len(decoded) == size:  # Might not equal our target size because of padding
            return decoded

    raise ValueError("Invalid value: could not decode as hex or base64")


def get_session_id(flask_request):
    return flask_request.headers.get("X-SOGS-Pubkey")


server_url = lambda room: '{}/{}?public_key={}'.format(config.URL_BASE, room or '', crypto.server_pubkey_hex)


# Size returned by make_legacy_token (assuming it is given a standard 66-hex (33 byte) session id):
LEGACY_TOKEN_SIZE = 64 + 33

def make_legacy_token(session_id):
    session_id = bytes.fromhex(session_id)
    return crypto.server_sign(session_id)
