#!/usr/bin/env python3

import os
import sys
from OpenSSL import crypto as c
from cryptography.hazmat.primitives import serialization as s
import argparse

parser = argparse.ArgumentParser(
    description="Convert old session-open-group-server key format to new key format"
)
parser.add_argument(
    "--in",
    "-i",
    dest="in_",
    type=str,
    metavar="OLD_KEY_FILE",
    help="Path to the session-open-group-server key file",
    default='./x25519_private_key.pem',
)
parser.add_argument(
    "--out",
    "-o",
    type=str,
    metavar="NEW_KEY_FILE",
    help="Path to the new sogs key to write",
    default='./key_x25519',
)
parser.add_argument("--overwrite", "-W", action='store_true')

args = parser.parse_args()

with open(args.in_) as f:
    pkey_pem = f.read()

if not args.overwrite and os.path.exists(args.out):
    print(
        f"Error: {args.out} already exists, not overwriting it without --overwrite flag!",
        file=sys.stderr,
    )
    sys.exit(1)

key = c.load_privatekey(c.FILETYPE_PEM, pkey_pem).to_cryptography_key()
pubkey_hex = key.public_key().public_bytes(encoding=s.Encoding.Raw, format=s.PublicFormat.Raw).hex()

print(f"Loaded private key; associated pubkey: {pubkey_hex}")

with open(os.open(args.out, os.O_CREAT | os.O_WRONLY, 0o400), 'wb') as f:
    f.write(
        key.private_bytes(
            encoding=s.Encoding.Raw,
            format=s.PrivateFormat.Raw,
            encryption_algorithm=s.NoEncryption(),
        )
    )

print("Wrote privkey to {}".format(args.out))
