#!/usr/bin/env python3

import sys
import nacl.bindings as sodium
import nacl.hash
import nacl.signing
from nacl.encoding import RawEncoder
from pyonionreq import xed25519

server_pk = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")

to_sign = "hello!"

for i in range(1000):
    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key
    xpk = pk.to_curve25519_public_key()
    sid = "05" + xpk.encode().hex()

    k25 = sodium.crypto_core_ed25519_scalar_reduce(
        nacl.hash.blake2b(
            bytes.fromhex(sid) + server_pk, digest_size=64, encoder=RawEncoder, key=b"SOGS_blind_v2"
        )
    )

    # Comment notation:
    # P = server pubkey
    # a/A = ed25519 keypair
    # b/B = x25519 keypair, converted from a/A
    # S = session id = 0x05 || B
    # T = |A|, that is, A with the sign bit cleared
    # t = private scalar s.t. tG = T (which is ± the private scalar associated with A)
    # k = blinding factor = H_64(S || P, key="SOGS_blind_v2")

    # This is simulating what the blinding client (i.e. with full keys) can compute:

    # k * A
    pk25a = sodium.crypto_scalarmult_ed25519_noclamp(k25, pk.encode())
    # -k * A
    neg_k25 = sodium.crypto_core_ed25519_scalar_negate(k25)
    pk25b = sodium.crypto_scalarmult_ed25519_noclamp(neg_k25, pk.encode())

    #    print(f"k: {k25.hex()}")
    #    print(f"-k: {neg_k25.hex()}")
    #
    #    print(f"a: {pk25a.hex()}")
    #    print(f"b: {pk25b.hex()}")

    assert pk25a != pk25b
    assert pk25a[0:31] == pk25b[0:31]
    assert pk25a[31] ^ 0x80 == pk25b[31]

    # The one we want to use is what we would end up with *if* our Ed25519 had been positive (but of
    # course there's a 50% chance it's negative).
    ed_pk_is_positive = pk.encode()[31] & 0x80 == 0

    pk25 = pk25a if ed_pk_is_positive else pk25b

    ###########
    # Make sure we can get to pk25 from the session id
    # We know sid and server_pk, so we can compute k25
    T_pk25 = sodium.crypto_scalarmult_ed25519_noclamp(k25, xed25519.pubkey(xpk.encode()))
    assert T_pk25 == pk25

    # To sign something that validates with pk25 we have a bit more work

    # First get our blinded, private scalar; we'll call it j

    # We want to pick j such that it is always associated with |A|, that is, our positive pubkey,
    # even if our pubkey is negative, so that someone with our session id can get our signing pubkey
    # deterministically.

    t = (
        sk.to_curve25519_private_key().encode()
    )  # The value we get here is actually our private scalar, despite the name
    if pk.encode()[31] & 0x80:
        # If our actual pubkey is negative then negate j so that it is as if we are working from the
        # positive version of our pubkey
        t = sodium.crypto_core_ed25519_scalar_negate(t)

    kt = sodium.crypto_core_ed25519_scalar_mul(k25, t)

    kT = sodium.crypto_scalarmult_ed25519_base_noclamp(kt)
    assert kT == pk25

    # Now we more or less follow EdDSA, but with our blinded scalar instead of real scalar, and with
    # a different hash function.  (See comments in libsession-util config/groups/keys.cpp for more
    # details).
    hseed = nacl.hash.blake2b(
        sk.encode()[0:31], key=b"SOGS25Seed", encoder=nacl.encoding.RawEncoder
    )
    r = sodium.crypto_core_ed25519_scalar_reduce(
        nacl.hash.blake2b(
            hseed + pk25 + to_sign.encode(), 64, key=b"SOGS25Sig", encoder=nacl.encoding.RawEncoder
        )
    )
    R = sodium.crypto_scalarmult_ed25519_base_noclamp(r)

    # S = r + H(R || A || M) a  (with A=kT, a=kt)
    hram = nacl.hash.sha512(R + kT + to_sign.encode(), encoder=nacl.encoding.RawEncoder)
    S = sodium.crypto_core_ed25519_scalar_reduce(hram)
    S = sodium.crypto_core_ed25519_scalar_mul(S, kt)
    S = sodium.crypto_core_ed25519_scalar_add(S, r)

    sig = R + S

    ###########################################
    # Test bog standard Ed25519 signature verification:

    vk = nacl.signing.VerifyKey(pk25)
    vk.verify(to_sign.encode(), sig)
