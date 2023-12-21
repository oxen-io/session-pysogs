#!/usr/bin/env python3

import sys
import nacl.bindings as sodium
import nacl.hash
import nacl.signing
from nacl.encoding import RawEncoder
from pyonionreq import xed25519

if len(sys.argv) < 3:
    print(
        f"Usage: {sys.argv[0]} SERVERPUBKEY {{SESSIONID|\"RANDOM\"}} [SESSIONID ...] -- blinds IDs",
        file=sys.stderr,
    )
    sys.exit(1)

server_pk = sys.argv[1]
sids = sys.argv[2:]

if len(server_pk) != 64 or not all(c in '0123456789ABCDEFabcdef' for c in server_pk):
    print(f"Invalid argument: expected 64 hex digit server pk as first argument")
    sys.exit(2)

server_pk = bytes.fromhex(server_pk)

print(nacl.hash.blake2b(server_pk, digest_size=64, encoder=RawEncoder))

k15 = sodium.crypto_core_ed25519_scalar_reduce(
    nacl.hash.blake2b(server_pk, digest_size=64, encoder=RawEncoder)
)


for i in range(len(sids)):
    if sids[i] == "RANDOM":
        sids[i] = (
            "05"
            + nacl.signing.SigningKey.generate()
            .verify_key.to_curve25519_public_key()
            .encode()
            .hex()
        )
    if (
        len(sids[i]) != 66
        or not sids[i].startswith('05')
        or not all(c in '0123456789ABCDEFabcdef' for c in sids[i])
    ):
        print(f"Invalid session id: expected 66 hex digit id as first argument")

print(f"SOGS pubkey: {server_pk.hex()}")

for s in sids:
    s = bytes.fromhex(s)

    if s[0] == 0x05:
        k25 = sodium.crypto_core_ed25519_scalar_reduce(
            nacl.hash.blake2b(s[1:] + server_pk, digest_size=64, encoder=RawEncoder)
        )

        pk15 = sodium.crypto_scalarmult_ed25519_noclamp(k15, xed25519.pubkey(s[1:]))
        pk25 = sodium.crypto_scalarmult_ed25519_noclamp(k25, xed25519.pubkey(s[1:]))

        print(
            f"{s.hex()} blinds to:\n    - 15{pk15.hex()} or …{pk15[31] ^ 0x80:02x}\n    - 25{pk25.hex()} or …{pk25[31] ^ 0x80:02x}"
        )
