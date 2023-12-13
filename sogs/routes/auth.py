from ..web import app
from ..db import query
from .. import config, crypto, http, utils
from ..model.user import User
from ..hashing import blake2b

from flask import request, abort, Response, g
import time
import nacl
from nacl.signing import VerifyKey
import nacl.exceptions
import nacl.bindings as sodium
import sqlalchemy.exc
from functools import wraps

# Authentication handling for incoming requests.

# We handle authentication through 4 headers included in the outermost request (e.g. which typically
# means the onion request):
#
# X-SOGS-Pubkey -- Ed25519 pubkey of the user.  If blinded, this starts with "15" and the pubkey is
# the user's blinded session id on the SOGS.  If *unblinded* this starts with "00", the remainder is
# an Ed25519 pubkey, and we convert it to an X25519 pubkey to determine the user's 05... session id.
#
# X-SOGS-Nonce -- a unique 128-bit (16 byte) request nonce, encoded in either base64 (22 chars (or
# 24 with optional padding)) or hex (32 characters).  This nonce may not be reused with this pubkey
# (within a reasonable time frame) and so should be randomly generated for each request.
#
# X-SOGS-Timestamp -- unix integer timestamp, expressed in the usual human (base 10) notation.  The
# timestamp must be with ±24 hours of the SOGS server time when the request is received.
#
# X-SOGS-Signature -- Ed25519 signature (passed in base64 encoding) of:
#
#       SERVER_PUBKEY || NONCE || TIMESTAMP || METHOD || PATH || HBODY
#
# where HBODY is 64-byte blake2b hash of the body *if* the request has a non-empty body, and is
# empty (omitted) otherwise.
#
# This value is signed using the blinded or unblinded Ed25519 pubkey given in the -Pubkey header.
#
# For example, for a GET request to '/capabilities?required=sogs' to a server with pubkey
# fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 the request headers could be:
#
# X-SOGS-Pubkey: 150123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# X-SOGS-Nonce: IYUVSYbLlTgmnigr/H3Tdg==
# X-SOGS-Timestamp: 1642079887
# X-SOGS-Signature: ...
#
# Where ... is the 88-character (including 2 padding chars) base64 encoding of the 64-byte value
# obtained by signing:
#
# b'xxx...xxxYYY...YYY1642079887GET/capabilities?required=sogs'
#   ^^^^^^^^^#########^^^^^^^^^^###^^^^^^^^^^^^^^^^^^^^^^^^^^^
#     `- server pubkey, 32B   |  |         |                  |
#               `- nonce, 16B |  |         |                  |
#                     TIMESTAMP  METHOD   PATH                `- (no body hash, because no body)
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
#   "X-SOGS-Signature": "...",
# }}
#
# you would calculate the 64-byte blake2b hash of '{"a":1}' (the onion request inner body), then
# sign:
#
# b'xxx...xxxYYY...YYY1642080374POST/some/endpointHHH...HHH'
#   ^^^^^^^^^#########^^^^^^^^^^####^^^^^^^^^^^^^^#########
#     `- server pubkey, 32B   |  |         |       |
#              `- nonce, 16B  |  |         |       |
#                      TIMESTAMP METHOD   PATH    HASH-BODY (64 bytes)
#
# For batch requests the X-SOGS-* headers are applied once, on the outermost batch request, *not* on
# the individual subrequests; the authorization applies to all subrequests.
#
# If `PATH` contains URL-encoded characters then the signature applies to the post-decoded value,
# e.g. a request for `GET /foo/%F0%9F%8D%8D%20%20%20%f0%9f%8d%8c` would expect the PATH component in
# the signature to be the utf8-encoded bytes of `/foo/🍍   🍌`.  (This is unfortunately necessary
# because HTTP request URL encoding rules are non-unique and could get converted between equivalent
# representations in transit).  If passing through an *onion request* then you may optionally avoid
# URL-encoding entirely: the endpoint of the onion request explicitly allows raw utf-8 characters in
# the path.  For direct requests, however, you should use the raw unicode value in the signature,
# but URL-encode the value in the actual HTTP request path.
#
# NB: legacy sogs endpoints (that is: endpoint paths without a leading /) require specifying the
# path in the signature message as `/legacy/whatever` even if just `whatever` is being used in the
# onion request "endpoint" parameter).


def abort_with_reason(code, msg, warn=True):
    if warn:
        app.logger.warning(msg)
    else:
        app.logger.debug(msg)
    abort(Response(msg, status=code, mimetype='text/plain'))


def require_user():
    """Requires that an authenticated user was found in the request headers; aborts with 401
    Unauthorized if the request had no user."""
    if g.user is None:
        abort_with_reason(http.UNAUTHORIZED, 'X-SOGS-* request authentication required')


def user_required(f):
    """Decorator for an endpoint that requires a user; this calls `require_user()` at the beginning
    of the request to abort the request as Unauthorized if valid authentication was not provided."""

    @wraps(f)
    def required_user_wrapper(*args, **kwargs):
        require_user()
        return f(*args, **kwargs)

    return required_user_wrapper


def require_blind_user():
    """Requires that the authenticated user is using a blinded pubkey for auth; aborts with 401
    Unauthorized if the user has not authenticated with a blinded pubkey."""
    require_user()
    if not g.user.is_blinded:
        abort_with_reason(http.UNAUTHORIZED, "This endpoint requires blinded pubkeys be used")


def blind_user_required(f):
    """Decorator for an endpoint that requires a user that is using a blinded public key;
    this calls `require_blind_user()` at the beginning
    of the request to abort the request as Unauthorized if that precondition is not met."""

    @wraps(f)
    def blind_user_wrapper(*args, **kwargs):
        require_blind_user()
        return f(*args, **kwargs)

    return blind_user_wrapper


def require_mod(room, *, admin=False):
    """Checks a room for moderator or admin permission; aborts with 401 Unauthorized if there is no
    user in the request, and 403 Forbidden if g.user does not have moderator (or admin, if
    specified) permission."""
    require_user()
    if not (room.check_admin(g.user) if admin else room.check_moderator(g.user)):
        abort_with_reason(
            http.FORBIDDEN,
            f"This endpoint requires {'admin' if admin else 'moderator'} room permissions",
        )


def accessible_required(f):
    """Decorator for an endpoint that requires a user have accessible or read permission in the
    given room.  The function must take a `room` argument by name, as is typically used with flask
    endpoints with a `<Room:room>` argument."""

    @wraps(f)
    def required_accessible_wrapper(*args, room, **kwargs):
        if not room.check_accessible(g.user):
            abort(http.NOT_FOUND)
        return f(*args, room=room, **kwargs)

    return required_accessible_wrapper


def read_required(f):
    """Decorator for an endpoint that requires a user have read permission in the given room.  The
    function must take a `room` argument by name, as is typically used with flask endpoints with a
    `<Room:room>` argument."""

    @wraps(f)
    def required_read_wrapper(*args, room, **kwargs):
        if not room.check_read(g.user):
            abort_with_reason(
                http.FORBIDDEN, "This endpoint requires room message 'read' permission"
            )
        return f(*args, room=room, **kwargs)

    return required_read_wrapper


def mod_required(f):
    """Decorator for an endpoint that requires a user that has moderator permission in the given
    room.  The function must take a `room` argument by name, as is typically used with flask
    endpoints with a <Room:room> argument."""

    @wraps(f)
    def required_mod_wrapper(*args, room, **kwargs):
        require_mod(room)
        return f(*args, room=room, **kwargs)

    return required_mod_wrapper


def admin_required(f):
    """Decorator for an endpoint that requires a user that has admin permission in the given room.
    The function must take a `room` argument by name, as is typically used with flask endpoints with
    a <Room:room> argument."""

    @wraps(f)
    def required_admin_wrapper(*args, room, **kwargs):
        require_mod(room, admin=True)
        return f(*args, room=room, **kwargs)

    return required_admin_wrapper


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
    - 403 Forbidden -- if the user validated successfully but is globally banned from the server.
    In either case we write an error description as plain text body of the error response.
    """

    # If we already have a g.user then we are probably a subrequest and want to preserve it, unless
    # user_reauth has been specifically set (from sogs.routes.subrequest).
    if hasattr(g, 'user') and not g.user_reauth:
        return

    g.user_reauth = False

    pk, nonce, ts_str, sig_in = (
        request.headers.get(f"X-SOGS-{h}") for h in ('Pubkey', 'Nonce', 'Timestamp', 'Signature')
    )

    missing = sum(x is None or x == '' for x in (pk, nonce, ts_str, sig_in))
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

    try:
        pk = utils.decode_hex_or_b64(pk, 33)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-SOGS-Pubkey is not a valid 66-hex digit id"
        )

    if pk[0] not in (0x00, 0x15, 0x25):
        abort_with_reason(
            http.BAD_REQUEST,
            "Invalid authentication: X-SOGS-Pubkey must be 00-, 15-, or 25- prefixed",
        )
    blinded15_pk = pk[0] == 0x15
    blinded25_pk = pk[0] == 0x25
    pk = pk[1:]

    if not sodium.crypto_core_ed25519_is_valid_point(pk):
        abort_with_reason(
            http.BAD_REQUEST,
            "Invalid authentication: given X-SOGS-Pubkey is not a valid Ed25519 pubkey",
        )

    pk = VerifyKey(pk)
    if blinded25_pk:
        session_id = '25' + pk.encode().hex()
    elif blinded15_pk and not config.REQUIRE_BLIND_V2:
        session_id = '15' + pk.encode().hex()
    elif config.REQUIRE_BLIND_KEYS:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: this server requires the use of blinded ids"
        )
    else:
        try:
            session_id = '05' + pk.to_curve25519_public_key().encode().hex()
        except nacl.exceptions.RuntimeError:
            abort_with_reason(
                http.BAD_REQUEST,
                "Invalid authentication: given X-SOGS-Pubkey is not a valid Ed25519 pubkey",
            )

    try:
        nonce = utils.decode_hex_or_b64(nonce, 16)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST,
            "Invalid authentication: X-SOGS-Nonce must be 16 bytes (encoded as base64 or hex)",
        )

    try:
        sig_in = utils.decode_hex_or_b64(sig_in, 64)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-SOGS-Signature is not base64[88]"
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

    user = User(session_id=session_id, autovivify=True, touch=False)
    if user.banned:
        # If the user is banned don't even bother verifying the signature because we want to reject
        # the request whether or not the signature validation passes.
        abort_with_reason(http.FORBIDDEN, 'Banned', warn=False)

    try:
        query('INSERT INTO user_request_nonces ("user", nonce) VALUES (:u, :n)', u=user.id, n=nonce)
    except sqlalchemy.exc.IntegrityError:
        abort_with_reason(http.TOO_EARLY, "Invalid authentication: X-SOGS-Nonce cannot be reused")

    # Signature validation

    # Signature should be on:
    #     SERVER_PUBKEY || NONCE || TIMESTAMP || METHOD || PATH || HBODY
    to_verify = (
        crypto.server_pubkey_bytes
        + nonce
        + ts_str.encode()
        + request.method.encode()
        + request.path.encode()
    )

    # Work around flask deficiency: we can't use request.full_path above because it *adds* a `?`
    # even if there wasn't one in the original request.  So work around it by only appending if
    # there is a query string and, officially, don't accept `?` followed by an empty query string in
    # the auth request data (if you have no query string then don't append the ?).
    if len(request.query_string):
        to_verify = to_verify + b'?' + request.query_string

    if len(request.data):
        to_verify = to_verify + blake2b(request.data, digest_size=64)

    try:
        pk.verify(to_verify, sig_in)
    except nacl.exceptions.BadSignatureError:
        abort_with_reason(
            http.UNAUTHORIZED, "Invalid authentication: X-SOGS-Signature verification failed"
        )

    user.touch()
    g.user = user
