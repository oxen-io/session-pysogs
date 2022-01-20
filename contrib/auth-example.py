# Example script for demonstrating X-SOGS-* authentication calculation.

from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey, PublicKey
from hashlib import blake2b
from base64 import b64encode

# import time
# import nacl.utils

# We're going to make a request for:
method = 'GET'
path = '/room/the-best-room/messages/recent?limit=25'
# Should use current integer unix time:
# ts = int(time.time())
# But for this example I'll use this fixed value:
ts = 1642472103

# Server pubkey:
B = PublicKey(bytes.fromhex('c3b3c6f32f0ab5a57f853cc4f30f5da7fda5624b0c77b3fb0829de562ada081d'))

# Don't worry, this isn't an actually used session private key.  Also
# note that this is the x25519 priv key, *not* the ed25519 priv key.
a = PrivateKey(bytes.fromhex('881132ee03dbd2da065aa4c94f96081f62142dc8011d1b7a00de83e4aab38ce4'))
A = a.public_key

# 057aecdcade88d881d2327ab011afd2e04c2ec6acffc9e9df45aaf78a151bd2f7d:
session_id = '05' + A.encode().hex()

# We should do something like this here:
# nonce = nacl.utils.random(16)
# but for this example I'll use this random nonce:
nonce = b'\t\xd0y\x9f"\x95\x99\x01\x82\xc3\xab4\x06\xfb\xfc['

# Shared key calculation:
q = crypto_scalarmult(a.encode(), B.encode()) + A.encode() + B.encode()
r = blake2b(q, digest_size=42, salt=nonce, person=b'sogs.shared_keys').digest()

# Final hash calculation; start without the body:
hasher = blake2b(
    method.encode() + path.encode() + str(ts).encode(),
    digest_size=42,
    key=r,
    salt=nonce,
    person=b'sogs.auth_header',
)

# Now add the body to the hash, if applicable.  For this GET request
# there is no body, so this update does nothing.  For a POST request this
# this would be the body bytes.  (By using a separate update call I avoid
# having to copy the body again, which is good if the body is large).
hasher.update(b'')

h = hasher.digest()

headers = {
    'X-SOGS-Pubkey': session_id,
    'X-SOGS-Timestamp': str(ts),
    'X-SOGS-Nonce': b64encode(nonce).decode(),
    'X-SOGS-Hash': b64encode(h).decode(),
}

for h, v in headers.items():
    print(f"{h}: {v}")

# Prints:
# X-SOGS-Pubkey: 057aecdcade88d881d2327ab011afd2e04c2ec6acffc9e9df45aaf78a151bd2f7d
# X-SOGS-Timestamp: 1642472103
# X-SOGS-Nonce: CdB5nyKVmQGCw6s0Bvv8Ww==
# X-SOGS-Hash: 0wToLPfUpUSGHGT8n9VIJev5SJ97hUvQTRqBowpnWTqfGb+ldTRa9mU1
