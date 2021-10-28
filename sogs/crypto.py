from . import config

import os

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
try:
    import pyonionreq
except ImportError:
    pyonionreq = None


# generate seed as needed
if not os.path.exists(config.SEED_FILE):
    with open(config.SEED_FILE, 'wb') as f:
        f.write(os.urandom(32))

with open(config.SEED_FILE, 'rb') as f:
    _privkey = SigningKey(seed=f.read())

server_pubkey = _privkey.verify_key

server_pubkey_hex = server_pubkey.encode(HexEncoder).decode('ascii')

parse_junk = lambda data: None

if pyonionreq:
    _junk = pyonionreq.junk.Parser(_privkey.to_curve25519_private_key(), server_pubkey.to_curve25519_public_key())
    parse_junk = _junk_parser.parse_junk

verify_sig_from_pk = lambda data, sig, pk: VerifyKey(pk).verify(data, sig)

verify_sig_from_server = server_pubkey.verify
