from . import crypto
from . import config
from . import http
from . import session_pb2 as protobuf

import base64
from flask import request, abort, Response
import json
from typing import Union, Tuple

def parse_message(data: bytes):
    """given a bunch of bytes for a protobuf message return the entire parsed message"""
    msg = protobuf.Content()
    msg.ParseFromString(remove_session_message_padding(data))
    return msg

def message_body(data: bytes):
    """given a bunch of bytes for a protobuf message return the message's body"""
    return parse_message(data).body

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
        decoded = decode_base64(data)
        if len(decoded) == size:  # Might not equal our target size because of padding
            return decoded

    raise ValueError("Invalid value: could not decode as hex or base64")


def _json_b64_impl(val):
    if isinstance(val, bytes) or isinstance(val, memoryview):
        return encode_base64(val)
    if isinstance(val, list):
        return [_json_b64_impl(v) for v in val]
    if isinstance(val, dict):
        return {_json_b64_impl(k): _json_b64_impl(v) for k, v in val.items()}
    return val


def json_with_base64(val):
    """
    Returns val encoded in json, but with any `bytes` or `memoryview` values encoded as base64
    strings.  Note that this base64-conversion only supports following lists and dicts.
    """
    return json.dumps(_json_b64_impl(val))


def jsonify_with_base64(val):
    """
    Returns a flask response set up for json (like flask.jsonify(...)), but uses json_with_base64
    for the encoding.
    """
    return Response(json_with_base64(val), mimetype="application/json")


def bencode_consume_string(body: memoryview) -> Tuple[memoryview, memoryview]:
    """
    Parses a bencoded byte string from the beginning of `body`.  Returns a pair of memoryviews on
    success: the first is the string byte data; the second is the remaining data (i.e. after the
    consumed string).
    Raises ValueError on parse failure.
    """
    pos = 0
    while pos < len(body) and 0x30 <= body[pos] <= 0x39:  # 1+ digits
        pos += 1
    if pos == 0 or pos >= len(body) or body[pos] != 0x3A:  # 0x3a == ':'
        raise ValueError("Invalid string bencoding: did not find `N:` length prefix")

    strlen = int(body[0:pos])  # parse the digits as a base-10 integer
    pos += 1  # skip the colon
    if pos + strlen > len(body):
        raise ValueError("Invalid string bencoding: length exceeds buffer")
    return body[pos : pos + strlen], body[pos + strlen :]


def server_url(room):
    # TODO: Once Session supports it, prefix this with /r/ so that SOGS pseudo-URLs for Session
    # coincide with the web viewer URL.
    return '{}/{}?public_key={}'.format(config.URL_BASE, room or '', crypto.server_pubkey_hex)


SIGNATURE_SIZE = 64
SESSION_ID_SIZE = 33
# Size returned by make_legacy_token (assuming it is given a standard 66-hex (33 byte) session id):
LEGACY_TOKEN_SIZE = SIGNATURE_SIZE + SESSION_ID_SIZE


def make_legacy_token(session_id):
    session_id = bytes.fromhex(session_id)
    return crypto.server_sign(session_id)


def legacy_convert_time(float_time):
    """take a float unix timestamp and convert it into something legacy Session likes"""
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


def remove_session_message_padding(data: bytes):
    """Removes the custom padding that Session may have added.  Returns the unpadded data."""

    # Except sometimes it isn't padded, so if we find something other than 0x00 or 0x80 *or* we
    # strip off all the 0x00's and then find something that isn't 0x80, then we're supposed to use
    # the whole thing (without the 0's stripped off).  Session code has a comment "This is dumb"
    # describing all of this.  I concur.
    if data and data[-1] in (0x00, 0x80):
        stripped_data = data.rstrip(b'\x00')
        if stripped_data and stripped_data[-1] == 0x80:
            data = stripped_data[:-1]
    return data


def add_session_message_padding(data: Union[bytes, memoryview], length):
    """Adds the custom padding that Session delivered the message with (and over which the signature
    is written).  Returns the padded value."""

    if length > len(data):
        if isinstance(data, memoryview):
            data = bytes(data)
        data += b'\x80' + b'\x00' * (length - len(data) - 1)
    return data
