from nacl.signing import SigningKey, VerifyKey
import nacl.bindings as salt
from nacl.utils import random
import nacl.hash
from hashlib import blake2b

from pyonionreq import xed25519

worked, trials = 0, 10000

pos_pk, neg_pk = 0, 0

for i in range(trials):
    s = SigningKey.generate()
    A = s.verify_key.encode()

    # This seems a bit weird, but: sodium's sk-to-curve uses the same private key scalar (a) for
    # both curves, so getting `a` for the curve25519 implicitly gives us the ed25519 `a` as well.
    a = salt.crypto_sign_ed25519_sk_to_curve25519(s.encode() + A)

    A_xpk = s.to_curve25519_private_key().public_key.encode()  # session id is 05 + this

    assert salt.crypto_scalarmult_ed25519_base_noclamp(a) == A
    assert salt.crypto_scalarmult_base(a) == A_xpk
    assert salt.crypto_core_ed25519_is_valid_point(A)

    server_pubkey = random(32)
    k = salt.crypto_core_ed25519_scalar_reduce(nacl.hash.generichash(server_pubkey, digest_size=64))

    ka = salt.crypto_core_ed25519_scalar_mul(k, a)
    # kA will be my blinded pubkey visible from my posts, with '15' prepended, and is an *Ed*
    # pubkey, not an X pubkey.
    kA = salt.crypto_scalarmult_ed25519_noclamp(k, A)

    assert salt.crypto_scalarmult_ed25519_base_noclamp(ka) == kA
    assert salt.crypto_core_ed25519_is_valid_point(kA)

    #############################
    # Signing (e.g. for X-SOGS-*) with a blinded keypair ka/kA

    # This generation is *almost* just bog standard Ed25519 but we have one change: when generating
    # r we add kA into the hash r = H(H_rh || kA || M), rather than r = H(H_rh || M), so that there
    # is domain separation for r for different blinded keys.  (H_rh here = right half of hash of the
    # secret key bytes.)  After that we do the standard Ed25519 `r + H(R || kA || M)a` calculation,
    # which gives us a bog standard Ed25519 that can be verified using the kA pubkey with standard
    # verification code.
    message_to_sign = b'omg happy days'
    H_rh = salt.crypto_hash_sha512(s.encode())[32:]
    r = salt.crypto_core_ed25519_scalar_reduce(salt.crypto_hash_sha512(H_rh + kA + message_to_sign))
    sig_R = salt.crypto_scalarmult_ed25519_base_noclamp(r)
    HRAM = salt.crypto_core_ed25519_scalar_reduce(
        salt.crypto_hash_sha512(sig_R + kA + message_to_sign)
    )
    sig_s = salt.crypto_core_ed25519_scalar_add(r, salt.crypto_core_ed25519_scalar_mul(HRAM, ka))
    full_sig = sig_R + sig_s

    assert VerifyKey(kA).verify(message_to_sign, full_sig)

    #############################
    # Sending a DM

    # Our user A above wants to send a SOGS DM to another user B:
    s2 = SigningKey.generate()
    B = s2.verify_key.encode()
    b = salt.crypto_sign_ed25519_sk_to_curve25519(s2.encode() + B)

    # with blinded keys:
    kb = salt.crypto_core_ed25519_scalar_mul(k, b)
    kB = salt.crypto_scalarmult_ed25519_noclamp(k, B)

    B_xpk = s2.to_curve25519_private_key().public_key.encode()

    assert salt.crypto_scalarmult_ed25519_base_noclamp(kb) == kB
    assert salt.crypto_core_ed25519_is_valid_point(kB)

    #############################
    # Finding friends:

    # For example (in reality this would come directly from the known session id):
    friend_xpk = salt.crypto_sign_ed25519_pk_to_curve25519(A)

    # From the session id (ignoring 05 prefix) we have two possible ed25519 pubkeys; the first is
    # the positive (which is what Signal's XEd25519 conversion always uses):
    pk1 = xed25519.pubkey(friend_xpk)

    # Blind it:
    pk1 = salt.crypto_scalarmult_ed25519_noclamp(k, pk1)

    # For the negative, what we're going to get out of the above is simply the negative of pk1, so
    # flip the sign bit to get pk2:
    pk2 = pk1[0:31] + bytes([pk1[31] ^ 0b1000_0000])

    # Optimization for Session:
    # - because the two blinded alternatives here differ by only the sign bit you can just always
    #   force the sign bit to be 0 when looking up a blinded -> real session id.  That is, when you
    #   store it, you compute pk1 as above, then do a `pk1[31] &= 0x7f` to clear the sign bit, and
    #   when looking up a blinded id to see if it's a friend, you also do the same bit clearing
    #   before looking it up (which saves having to store two keys for each contact/server
    #   combination).

    # This calculation is completely unnecessary and is only here to verify that going the long way
    # around gives the same result as the shortcut:
    pk2_alt = xed25519.pubkey(friend_xpk)
    pk2_alt = pk2_alt[0:31] + bytes([pk2_alt[31] | 0b1000_0000])
    pk2_alt = salt.crypto_scalarmult_ed25519_noclamp(k, pk2_alt)
    assert pk2 == pk2_alt

    # Now, if this is really my friend, his blinded key will equal one of these blinded keys:
    if kA == pk1:
        pos_pk += 1
    elif kA == pk2:
        neg_pk += 1
    else:
        # not my friend
        print("failed; got neither ±A")
        continue

    #############################
    # Encrypting a SOGS DM
    msg = 'hello 🎂'

    # Step one: calculate a shared secret, sending from A to B.  We're going to calculate:
    #
    # BLAKE2b(a kB || kA || kB)
    #
    # from the sender, and the receiver can calculate this same value as:
    #
    # BLAKE2b(b kA || kA || kB)
    #
    enc_key = blake2b(
        salt.crypto_scalarmult_ed25519_noclamp(a, kB) + kA + kB, digest_size=32
    ).digest()

    # Inner data: msg || A   (i.e. the sender's ed25519 master pubkey, *not* kA blinded pubkey)
    plaintext = msg.encode() + A

    # Encrypt using xchacha20-poly1305
    nonce = random(24)
    ciphertext = salt.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad=None, nonce=nonce, key=enc_key
    )

    data = b'\x00' + ciphertext + nonce

    #############################
    # Decrypting a SOGS DM
    # Opening the box on the recipient end.

    # I receive alongside the message from sogs (i.e. this is the blinded session id minus the '15')
    # kA=...

    # Calculate the shared encryption key (see above)
    dec_key = blake2b(
        salt.crypto_scalarmult_ed25519_noclamp(b, kA) + kA + kB, digest_size=32
    ).digest()

    assert enc_key == dec_key

    assert len(data) > 25
    v, ct, nc = data[0], data[1:-24], data[-24:]

    assert v == 0x00  # Make sure our encryption version is okay

    # Decrypt
    plaintext = salt.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad=None, nonce=nc, key=dec_key)

    assert len(plaintext) > 32

    # Split up: the last 32 bytes are the sender's *unblinded* ed25519 key
    message, sender_edpk = plaintext[:-32], plaintext[-32:]

    # Verify that the inner sender_edpk (A) yields the same outer kA we got with the message
    assert kA == salt.crypto_scalarmult_ed25519_noclamp(k, sender_edpk)

    message = message.decode()  # utf-8 bytes back to str

    sender_session_id = '05' + salt.crypto_sign_ed25519_pk_to_curve25519(sender_edpk).hex()

    assert message == msg
    assert sender_edpk == A
    assert sender_session_id == '05' + A_xpk.hex()

    worked += 1


print(f"{worked} successes / {trials} trials")
print(f"{pos_pk} positive Ed keys, {neg_pk} negative")
