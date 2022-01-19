from ..web import app
from ..db import query
from .. import crypto, http, utils
from ..model.user import User

from flask import request, abort, Response, g
import string
import time
from nacl.bindings import crypto_scalarmult
from nacl.encoding import RawEncoder
import nacl.hash
import nacl.hashlib
import sqlalchemy.exc

# Authentication handling for incoming requests.

# We handle authentication through 4 headers included in the outermost request (e.g. which typically
# means the onion request):
#
# X-SOGS-Pubkey -- the blinded session_id of the user, in its typical hex representation.  This is
# typically a blinded id starting with "bb" rather than "05".
#
# X-SOGS-Nonce -- a unique 128-bit (16 byte) request nonce, encoded in either base64 (22 chars (or
# 24 with optional padding)) or hex (32 characters).  This nonce may not be reused with this pubkey
# (within a reasonable time frame) and so should be randomly generated for each request.
#
# X-SOGS-Timestamp -- unix integer timestamp, expressed in the usual human (base 10) notation.  The
# timestamp must be with ±24 hours of the SOGS server time when the request is received.
#
# X-SOGS-Hash -- base64 encoding of the keyed hash of:
#
#       METHOD || PATH || TIMESTAMP || BODY
#
# using a Blake2B 42-byte keyed hash (to be obviously different from things like 32-byte pubkeys and
# 64-byte signatures, and because 42 encodes cleanly into base64), where the hash is calculated as:
#
#     a (≡ user x25519 privkey, *not* including 05 Session prefix)
#     A (≡ user x25519 pubkey)
#     B (≡ server pubkey)
#
#     q = a*B
#     shared_key = Blake2B(
#         q || A || B,
#         digest_size=42,
#         salt=nonce,
#         person=b'sogs.shared_keys')
#     hash = Blake2B(
#         data=M || P || T || B,
#         digest_size=42,
#         key=shared_key,
#         salt=nonce,
#         person=b'sogs.auth_header')
#
# For example, for a GET request to '/capabilities?required=sogs' to a server with pubkey
# fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 the request headers could be:
#
# X-SOGS-Pubkey: 050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# X-SOGS-Nonce: IYUVSYbLlTgmnigr/H3Tdg==
# X-SOGS-Timestamp: 1642079887
# X-SOGS-Hash: ...
#
# Where ... is the 56-character base64 encoding of the 42-byte value obtained by hashing:
#
# b'GET/capabilities?required=sogs1642079887'
#   ^^^###########################^^^^^^^^^^
#  METHOD    PATH (incl. query)   TIMESTAMP   (empty BODY)
#
# using the blake2b hash as described above.
#
# Or for a onion POST request with a body:
#
# POST /oxen/v3/lsrpc
#
# with the (post-decryption) body containing:
#
# {"endpoint": "/some/endpoint", "method": "POST", "body": "{\"a\":1}", "headers": {
#   "X-SOGS-Pubkey": "050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
#   "X-SOGS-Nonce": "5f9369b79449a7dfa07d123b697c84f6",  # random, hex encoded
#   "X-SOGS-Timestamp": "1642080374",
#   "X-SOGS-Hash": "...",
# }}
#
# where now the hash field is the base64 encoding of the hash of the value:
#
# b'POST/some/endpoint1642080374{"a":1}'
#   ^^^^##############^^^^^^^^^^#######
#  METHOD  ENDPOINT   TIMESTAMP  BODY
#
# (Note that the hash here is identical whether submitted via direct POST request or wrapped in an
# onion request; an onion request is described for exposition).
#
# For batch requests the X-SOGS-* headers are applied once, on the outermost batch request, *not* on
# the individual subrequests; the authorization applies to all subrequests.
#
# NB: legacy sogs endpoints (that is: endpoint paths without a leading /) will not work with this
# authentication mechanism; in order to call them you must invoke them with a leading `/legacy/`
# prefix (e.g. `GET /legacy/rooms`).


def abort_with_reason(code, msg):
    app.logger.warning(msg)
    abort(Response(msg, status=code, mimetype='text/plain'))


def require_user():
    """Requires that an authenticated user was found in the request headers; aborts with 401
    Unauthorized if the request had no user."""
    if g.user is None:
        abort_with_reason(http.UNAUTHORIZED, 'X-SOGS-* request authentication required')


@app.before_request
def handle_http_auth():
    """
    Verifies authentication information from the request headers/body, if present.  If
    authentication is present this sets g.user to the authenticated model.user.User (creating and/or
    touching its last activity timestamp).  If there are no auth headers at all this sets g.user to
    None.

    If authentication headers are present but are unparseable (e.g. wrong size nonce, or failure to
    decode, or one or more of the headers are missing) then this throws a flask abort with a 400 Bad
    Request response.  Otherwise this can return a request error of:
    - 401 Unauthorized -- invalid signature, for example because of nonce reuse or signature
      verification failure
    - 425 Too Early -- if the timestamp is too far from the server time (more than 24h off), or the
      client is attempting to reuse a nonce.
    In either case we write an error description as plain text body of the error response.
    """

    # If we already have a g.user then we are probably a subrequest and want to preserve it, unless
    # user_reauth has been specifically set (from sogs.routes.subrequest).
    if hasattr(g, 'user') and not g.user_reauth:
        return

    g.user_reauth = False

    pk, nonce, ts_str, hash_in = (
        request.headers.get(f"X-SOGS-{h}") for h in ('Pubkey', 'Nonce', 'Timestamp', 'Hash')
    )

    missing = sum(x is None or x == '' for x in (pk, nonce, ts_str, hash_in))
    # If all are missing then we have no user
    if missing == 4:
        g.user = None
        return

    if missing:
        abort_with_reason(
            http.BAD_REQUEST,
            f"Invalid authentication headers: missing {missing}/4 required X-SOGS-* headers",
        )

    # Parameter input validation

    # TODO: accept/support blinded keys with some other prefix (maybe "15" or "bb" or "55"?)
    if len(pk) != 66 or pk[0:2] != "05" or not all(x in string.hexdigits for x in pk):
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-SOGS-Pubkey is not a valid 66-hex digit id"
        )
    A = bytes.fromhex(pk[2:])

    try:
        nonce = utils.decode_hex_or_b64(nonce, 16)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST,
            "Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)",
        )

    try:
        hash_in = utils.decode_hex_or_b64(hash_in, 42)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST,
            "Invalid authentication: X-SOGS-Hash is not base64[56] or hex[84]",
        )

    try:
        ts = int(ts_str)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-SOGS-Timestamp is not a valid timestamp"
        )

    # Parameter value validation

    now = time.time()
    if not now - 24 * 60 * 60 <= ts <= now + 24 * 60 * 60:
        abort_with_reason(
            http.TOO_EARLY, "Invalid authentication: X-SOGS-Timestamp is too far from current time"
        )

    user = User(session_id=pk, autovivify=True, touch=False)

    try:
        query('INSERT INTO user_request_nonces ("user", nonce) VALUES (:u, :n)', u=user.id, n=nonce)
    except sqlalchemy.exc.IntegrityError:
        abort_with_reason(http.TOO_EARLY, "Invalid authentication: X-SOGS-Nonce cannot be reused")

    # Hash validation

    # shared_key is hash of a*B || A || B = b*A || A || B where b/B is the server keypair and A is
    # the session id pubkey.
    shared_key = nacl.hash.blake2b(
        crypto_scalarmult(crypto._privkey.encode(), A) + A + crypto.server_pubkey_bytes,
        digest_size=42,
        salt=nonce,
        person=b'sogs.shared_keys',
        encoder=RawEncoder,
    )

    hasher = nacl.hashlib.blake2b(
        request.method.encode() + request.path.encode(),
        digest_size=42,
        key=shared_key,
        salt=nonce,
        person=b'sogs.auth_header',
    )

    # Work around flask deficiency: we can't use request.full_path above because it *adds* a `?`
    # even if there wasn't one in the original request.  So work around it by only appending if
    # there is a query string and, officially, don't accept `?` followed by an empty query string in
    # the auth request data (if you have no query string then don't append the ?).
    if len(request.query_string):
        hasher.update(b'?')
        hasher.update(request.query_string)
    hasher.update(ts_str.encode())

    if len(request.data):
        hasher.update(request.data)
    expected = hasher.digest()

    if expected != hash_in:
        abort_with_reason(
            http.UNAUTHORIZED, "Invalid authentication: X-SOGS-Hash authentication failed"
        )

    user.touch()
    g.user = user
