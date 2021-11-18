import base64

from . import crypto
from . import config
from . import http
from . import session_pb2 as protobuf

from flask import request, abort


def message_body(data: bytes):
    """given a bunch of bytes for a protobuf message return the message's body"""
    msg = protobuf.DataMessage()
    msg.ParseFromString(data)
    return msg.body


def encode_base64(data: bytes):
    return base64.b64encode(data).decode()


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

    if len(data) == size * 2:
        return bytes.fromhex(data)

    b64_size = (size + 2) // 3 * 4  # bytes*4/3, rounded up to the next multiple of 4.
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


def server_url(room):
    return '{}/{}?public_key={}'.format(config.URL_BASE, room or '', crypto.server_pubkey_hex)


SIGNATURE_SIZE = 64
SESSION_ID_SIZE = 33
# Size returned by make_legacy_token (assuming it is given a standard 66-hex (33 byte) session id):
LEGACY_TOKEN_SIZE = SIGNATURE_SIZE + SESSION_ID_SIZE


def make_legacy_token(session_id):
    session_id = bytes.fromhex(session_id)
    return crypto.server_sign(session_id)


def convert_time(float_time):
    """take a float and convert it into something session likes"""
    return int(float_time * 1000)


def get_int_param(name, default=None, *, required=False, min=None, max=None, truncate=False):
    """
    Returns a provided named parameter (typically a query string parameter) as an integer from the
    current request.  On error we abort the request with a Bad Request error status code.

    Parameters:
    - required -- if True then not specifying the argument is an error.
    - default -- if the parameter is not given then return this.  Ignored if `required` is true.
    - min -- the minimum acceptable value for the parameter; None means no minimum.
    - max -- the maximum acceptable value for the parameter; None means no maximum.
    - truncate -- if True then we truncate a >max or <min value to max or min, respectively.  When
      False (the default) we error.
    """
    val = request.args.get(name)
    if val is None:
        if required:
            abort(http.BAD_REQUEST)
        return default

    try:
        val = int(val)
    except Exception:
        abort(http.BAD_REQUEST)

    if min is not None and val < min:
        if truncate:
            val = min
        else:
            abort(http.BAD_REQUEST)
    elif max is not None and val > max:
        if truncate:
            val = max
        else:
            abort(http.BAD_REQUEST)
    return val
