# DMs

Direct messages between blinded users

## Encryption details

SOGS itself does not have the ability to decrypt the message contents and thus cannot enforce
any particular content; the following, however, is strongly recommended for Session client
interoperability:

Alice has master Session Ed25519 keypair `a`, `A` and blinded keypair `ka`, `kA`.

Bob has master Session Ed25519 keypair `b`, `B` and blinded keypair `kb`, `kB`.

Alice wants to send a message to Bob, knowing only `kB` (i.e. the blinded Session ID after
stripping the `0x15` prefix).

Alice constructs a message using Session protobuf encoding, then concatenates her *unblinded*
pubkey, `A`, to this message:

    MSG || A

Alice then constructs an encryption key:

    E = H(a * kB || kA || kB)

where `H(.)` is 32-byte BLAKE2b, and the `*` denotes unclamped Ed25519 scalar*point multiplication
(e.g. libsodium's `crypto_scalarmult_ed25519_noclamp`).

The `MSG || A` plaintext value is then encrypted using XChaCha20-Poly1305 (e.g. using
libsodium's `crypto_aead_xchacha20poly1305_ietf_encrypt` function), using a secure-random
24-byte nonce, no additional data, and encryption key `E`.

The final data message is then constructed as:

    0x00 || CIPHERTEXT || NONCE

where 0x00 is a version byte (allowing for future alternative encryption formats) and the rest
are bytes.

Finally this is base64-encoded when send to/retrieved from the SOGS.

## Decryption

Decryption proceeds by reversing the steps above:

1. base64-decode the value.

2. Grab the version byte from the front and the 24-byte nonce from the back of the value.

    a) if the version byte is not `0x00` abort because this message is from someone using a
    different encryption protocol.

3. Construct the encryption key by calculating:

        E = H(b * kA || kA || kB)

    where `kA` is the sender's de-prefixed blinded Session ID, `b` is the user's master Ed25519 key,
    and `kB` is the user's blinded Ed25519 for this SOGS server.

4. Decrypt the remaining ciphertext using the nonce.

5. Unpack the plaintext value into MSG and the sender's `A` value (i.e. the last 32 bytes).

6. Derive the sender's actual Session ID by converting `A` from an ed25519 pubkey to an
   curve25519 pubkey and prepending 0x05.  (E.g. using libsodium's
   `crypto_sign_ed25519_pk_to_curve25519` on `A`, then adding the `05` prefix to the front).

This then leaves the receiving client with the true Session ID of the sender, and the message
body (encoded according to typical Session message protobuf encoding).
