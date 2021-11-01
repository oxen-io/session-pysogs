#!/usr/bin/env python3

import os
import sys
from OpenSSL import crypto as c
from cryptography.hazmat.primitives import serialization as s
from sogs import config

with open('x25519_private_key.pem') as f:
    pkey_pem = f.read()

if os.path.exists(config.SEED_FILE):
    print("Error: {} already exists, not overwriting it!", file=sys.stderr)

key = c.load_privatekey(c.FILETYPE_PEM, pkey_pem).to_cryptography_key()
pubkey_hex = key.public_key().public_bytes(encoding=s.Encoding.Raw, format=s.PublicFormat.Raw).hex()

print("Loaded private key; associated pubkey: {}".format(pubkey_hex))

with open(config.SEED_FILE, 'wb') as f:
    f.write(key.private_bytes(
        encoding=s.Encoding.Raw,
        format=s.PrivateFormat.Raw,
        encryption_algorithm=s.NoEncryption()))

print("Wrote privkey to {}".format(config.SEED_FILE))
