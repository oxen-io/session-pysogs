from flask import request, abort, Blueprint
import json

from ..web import app
from .. import crypto, http, utils

from .subrequest import make_subrequest

from session_util.onionreq import OnionReqParser

onion_request = Blueprint('onion_request', __name__)


def handle_v3_onionreq_plaintext(body):
    """
    Handles a decrypted v3 onion request; this injects a subrequest to process it then returns the
    result of that subrequest (as bytes).

    The body must be JSON containing two always-required keys:

    - "endpoint" -- the HTTP endpoint to invoke (e.g. "/room/some-room").
    - "method" -- the HTTP method (e.g. "POST", "GET")

    Plus, when method is POST or PUT, the required field:

    - "body" -- the request body for POST/PUT requests

    Optional keys that may be included are:
    - "headers" -- optional dict of HTTP headers for the request.  Header names are
                   case-insensitive (i.e. `X-Foo` and `x-FoO` are equivalent).

    If "endpoint" does not start with a "/" then the request is a legacy endpoint request, and two
    things happen:
    - "/legacy/" will be prepended to the endpoint.  E.g. "endpoint":"rooms/ROOM/image" goes to the
      "/legacy/rooms/ROOM/image" endpoint in pysogs.
    - we will look "auth_code" in the json -- if specified, this is equivalent to specifying the
      "Authorization" header with the given value (this is used for user authentication for legacy
      sogs requests.)

    When returning, we invoke the subrequest and then, if it returns a 200 response code, we take
    the response body, encrypt it, and then base64 the encrypted body and send that back as the
    response body of the onion request.

    If the subrequest returned a non-200 response code then instead of the returned body we return
    `{"status_code":xxx}` (where xxx is the numeric status code) and encrypt/base64 encode that.

    Response headers are completely ignored, as are bodies of non-200 responses.

    This is deprecated because it amplifies request and response sizes, it doesn't allow non-json
    requests, and it drops pertinent request information (such as response headers and error
    bodies).  Prefer v4 requests which do not have these drawbacks.
    """

    try:
        if not body.startswith(b'{'):
            raise RuntimeError("Invalid v3 onion request body: expected JSON object")

        req = json.loads(body)
        endpoint, method, auth_code = req['endpoint'], req['method'], req.get("auth_code")
        subreq_headers = {k.lower(): v for k, v in req.get('headers', {}).items()}

        if method in http.BODY_METHODS:
            subreq_body = req.get('body', '').encode()
        else:
            subreq_body = None
            # Android bug workaround: Android Session (at least up to v1.11.12) sends a body on
            # GET requests with a 4-character string "null" when it should send no body.
            if 'body' in req and len(req['body']) == 4 and req['body'] == 'null':
                del req['body']

            if 'body' in req and req['body']:
                raise RuntimeError(
                    "Invalid {} {} request: request must not contain a body".format(
                        method, endpoint
                    )
                )

        if not endpoint.startswith('/'):
            endpoint = '/legacy/' + endpoint
            if auth_code:
                subreq_headers["Authorization"] = auth_code

        response, _headers = make_subrequest(
            method,
            endpoint,
            headers=subreq_headers,
            body=subreq_body,
            content_type='application/json',
            user_reauth=True,  # Because onion requests have auth headers on the *inside*
        )

        if 200 <= response.status_code < 300:
            data = response.get_data()
            app.logger.debug(
                f"Onion sub-request for {endpoint} returned success, {len(data)} bytes"
            )
            return data
        return json.dumps({'status_code': response.status_code}).encode()

    except Exception as e:
        app.logger.warning("Invalid onion request: {}".format(e))
        return json.dumps({'status_code': http.BAD_REQUEST}).encode()


def handle_v4_onionreq_plaintext(body):
    """
    Handles a decrypted v4 onion request; this injects a subrequest to process it then returns the
    result of that subrequest.  In contrast to v3, it is more efficient (particularly for binary
    input or output) and allows using endpoints that return headers or bodies with non-2xx response
    codes.

    The body of a v4 request (post-decryption) is a bencoded list containing exactly 1 or 2 byte
    strings: the first byte string contains a json object containing the request metadata which has
    three required fields:

    - "endpoint" -- the HTTP endpoint to invoke (e.g. "/room/some-room").
    - "method" -- the HTTP method (e.g. "POST", "GET")
    - "headers" -- dict of HTTP headers for the request.  Header names are case-insensitive (i.e.
      `X-Foo` and `x-FoO` are equivalent).

    Unlike v3 requests, endpoints must always start with a /.  (If a legacy endpoint "whatever"
    needs to be accessed through a v4 request for some reason then it can be accessed via the
    "/legacy/whatever" endpoint).

    If an "endpoint" contains unicode characters then it is recommended to provide it as direct
    UTF-8 values (rather than URL-encoded UTF-8).  Both approaches will work, but the X-SOGS-*
    authentication headers will always apply on the final, URL-decoded value and so avoiding
    URL-encoding in the first place will typically simplify client implementations.

    The "headers" field typically carries X-SOGS-* authentication headers as well as fields like
    Content-Type.  Note that, unlike v3 requests, the Content-Type does *not* have any default and
    should also be specified, often as `application/json`.  Unlike HTTP requests, Content-Length is
    not required and will be ignored if specified; the content-length is always determined from the
    provided body.

    The second byte string in the request, if present, is the request body in raw bytes and is
    required for POST and PUT requests and must not be provided for GET/DELETE requests.

    Bencoding details:
        A full bencode library can be used, but the format used here is deliberately meant to be as
        simple as possible to implement without a full bencode library on hand.  The format of a
        byte string is `N:` where N is a decimal number (e.g. `123:` starts a 123-byte string),
        followed by the N bytes.  A list of strings starts with `l`, contains any number of encoded
        byte strings, followed by `e`.  (Full bencode allows dicts, integers, and list/dict
        recursion, but we do not use any of that for v4 bencoded onion requests).

    For example, the request:

        GET /room/some-room
        Some-Header: 12345

    would be encoded as:

        l79:{"method":"GET","endpoint":"/room/some-room","headers":{"Some-Header":"12345"}}e

    that is: a list containing a single 79-byte string.  A POST request such as:

        POST /some/thing
        Some-Header: a

        post body here

    would be encoded as the two-string bencoded list:

        l72:{"method":"POST","endpoint":"/some/thing","headers":{"Some-Header":"a"}}14:post body heree
            ^^^^^^^^72-byte request info json^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^body^^^^^

    The return value of the request is always a 2-part bencoded list where the first part contains
    response metadata and the second contains the response body.  The response metadata is a json
    object containing:
    - "code" -- the numeric HTTP response code (e.g. 200, 403); and
    - "headers" -- a json object of header names to values.  Note that, since HTTP headers are
      case-insensitive, the header names are always returned as lower-case, and we strip out the
      'content-length' header (since it is already encoded in the length of the body part).

    For example, a simple json request response might be the two parts:

    - `{"code":200,"headers":{"content-type":"application/json"}}`
    - `{"id": 123}`

    encoded as:

        l58:{"code":200,"headers":{"content-type":"application/json"}}11:{"id": 123}e

    A more complicated request, for example for a file download, might return binary content such as:

    - `{"code":200,"headers":{"content-type":"application/octet-stream","content-disposition":"attachment; filename*=UTF-8''filename.txt"}}`
    - `My file contents`

    i.e. encoded as `l132:{...the json above...}16:My file contentse`

    Error responses (e.g. a 403) are not treated specially; that is: they still have a "code" set to
    the response code and "headers" and a body part of whatever the request returned for a body).

    The final value returned from the endpoint is the encrypted bencoded bytes, and these encrypted
    bytes are returned directly to the client (i.e. no base64 encoding applied, unlike v3 requests).
    """  # noqa: E501

    try:
        if not (body.startswith(b'l') and body.endswith(b'e')):
            raise RuntimeError("Invalid onion request body: expected bencoded list")

        belems = memoryview(body)[1:-1]

        # Metadata json; this element is always required:
        meta, belems = utils.bencode_consume_string(belems)

        meta = json.loads(meta.tobytes())

        # Then we can have a second optional string containing the body:
        if len(belems) > 1:
            subreq_body, belems = utils.bencode_consume_string(belems)
            if len(belems):
                raise RuntimeError("Invalid v4 onion request: found more than 2 parts")
        else:
            subreq_body = b''

        method, endpoint = meta['method'], meta['endpoint']
        if not endpoint.startswith('/'):
            raise RuntimeError("Invalid v4 onion request: endpoint must start with /")

        response, headers = make_subrequest(
            method,
            endpoint,
            headers=meta.get('headers', {}),
            body=subreq_body,
            user_reauth=True,  # Because onion requests have auth headers on the *inside*
        )

        data = response.get_data()
        app.logger.debug(
            f"Onion sub-request for {endpoint} returned {response.status_code}, {len(data)} bytes"
        )

        meta = {'code': response.status_code, 'headers': headers}

    except Exception as e:
        app.logger.warning("Invalid v4 onion request: {}".format(e))
        meta = {'code': http.BAD_REQUEST, 'headers': {'content-type': 'text/plain; charset=utf-8'}}
        data = b'Invalid v4 onion request'

    meta = json.dumps(meta).encode()
    return b''.join(
        (b'l', str(len(meta)).encode(), b':', meta, str(len(data)).encode(), b':', data, b'e')
    )


def decrypt_onionreq():
    try:
        return OnionReqParser(crypto.server_pubkey_bytes, crypto._privkey_bytes, request.data)
    except Exception as e:
        app.logger.warning("Failed to decrypt onion request: {}".format(e))
    abort(http.BAD_REQUEST)


@onion_request.post("/oxen/v3/lsrpc")
@onion_request.post("/loki/v3/lsrpc")
def handle_v3_onion_request():
    """
    Parse an onion request, handle it as a subrequest, then throw away the subrequest headers,
    replace the subrequest body with a json string, encrypt the final result and then pointlessly
    base64 encodes the body before sending it back to the requestor.

    Deprecated in favour of /v4/.
    """

    parser = decrypt_onionreq()
    return utils.encode_base64(parser.encrypt_reply(handle_v3_onionreq_plaintext(parser.payload)))


@onion_request.post("/oxen/v4/lsrpc")
def handle_v4_onion_request():
    """
    Parse a v4 onion request.  See handle_v4_onionreq_plaintext().
    """

    # Some less-than-ideal decisions in the onion request protocol design means that we are stuck
    # dealing with parsing the request body here in the internal format that is meant for storage
    # server, but the *last* hop's decrypted, encoded data has to get shared by us (and is passed on
    # to us in its raw, encoded form).  It looks like this:
    #
    # [N][blob][json]
    #
    # where N is the size of blob (4 bytes, little endian), and json contains *both* the elements
    # that were meant for the last hop (like our host/port/protocol) *and* the elements that *we*
    # need to decrypt blob (specifically: "ephemeral_key" and, optionally, "enc_type" [which can be
    # used to use xchacha20-poly1305 encryption instead of AES-GCM]).
    #
    # The parse_junk here takes care of decoding and decrypting this according to the fields *meant
    # for us* in the json (which include things like the encryption type and ephemeral key):
    try:
        parser = decrypt_onionreq()
    except RuntimeError as e:
        app.logger.warning("Failed to decrypt onion request: {}".format(e))
        abort(http.BAD_REQUEST)

    # On the way back out we re-encrypt via the junk parser (which uses the ephemeral key and
    # enc_type that were specified in the outer request).  We then return that encrypted binary
    # payload as-is back to the client which bounces its way through the SN path back to the client.
    response = handle_v4_onionreq_plaintext(parser.payload)
    return parser.encrypt_reply(response)
