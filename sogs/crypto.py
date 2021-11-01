from . import config

import os

from nacl.public import PrivateKey, PublicKey
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
import pyonionreq

# generate seed as needed
if not os.path.exists(config.SEED_FILE):
    with open(config.SEED_FILE, 'wb') as f:
        f.write(PrivateKey.generate().encode())

with open(config.SEED_FILE, 'rb') as f:
    _privkey = PrivateKey(f.read())

server_pubkey = _privkey.public_key

server_pubkey_hex = server_pubkey.encode(HexEncoder).decode('ascii')

_junk_parser = pyonionreq.junk.Parser(privkey=_privkey.encode(), pubkey=server_pubkey.encode())
parse_junk = _junk_parser.parse_junk

verify_sig_from_pk = lambda data, sig, pk: VerifyKey(pk).verify(data, sig)
