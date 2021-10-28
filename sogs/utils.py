import base64
import binascii

def decode_hex_or_b64(data):
    try:
        return base64.b64decode(data)
    except:
        pass
    try:
        return binascii.unhexlify(data)
    except:
        raise

def get_session_id(flask_request):
    return flask_request.headers.get("X-SOGS-Pubkey")
