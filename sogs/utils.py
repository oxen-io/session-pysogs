import base64
import binascii

from . import crypto
from . import config

encode_base64 = base64.b64encode

def decode_hex_or_b64(data):
    if data is None:
        return
    try:
        return binascii.unhexlify(data)
    except:
        raise
    try:
        return base64.b64decode(data)
    except:
        pass

def get_session_id(flask_request):
    return flask_request.headers.get("X-SOGS-Pubkey")


server_url = lambda room: '{}/{}?public_key={}'.format(config.URL_BASE, room or '', crypto.server_pubkey_hex)


def make_legacy_token(session_id):
    session_id = session_id.encode('ascii')
    return session_id + crypto.server_sign(session_id)
