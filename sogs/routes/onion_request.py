from flask import request, abort, Blueprint
import json

from ..web import app
from .. import crypto, http, utils

from .subrequest import make_subrequest

onion_request = Blueprint('onion_request', __name__)


def handle_onionreq_plaintext(body):
    """
    Handles a decrypted onion request; this injects a subrequest to process it then returns the
    result of that subrequest (as bytes).

    Note that this does not throw: if errors occur we map them into "success" responses with a body
    of {"status_code":xxx} as onion requests have no ability at all to signal a request failure.
    """
    try:
        if body.startswith(b'{'):
            # JSON input
            req = json.loads(body)
            endpoint, method, auth_code = req['endpoint'], req['method'], req.get("auth_code")
            subreq_headers = {k.lower(): v for k, v in req.get('headers', {}.items()).items()}

            if method in http.BODY_METHODS:
                if 'body_binary' in req:
                    subreq_body = utils.decode_base64(req['body_binary'])
                else:
                    subreq_body = req.get('body', '').encode()
                ct = subreq_headers.pop(
                    'content-type',
                    'application/octet-stream' if 'body_binary' in req else 'application/json',
                )
            else:
                subreq_body = None
                # Android bug workaround: Android Session (at least up to v1.11.12) sends a body on
                # GET requests with a 4-character string "null" when it should send no body.
                if 'body' in req and len(req['body']) == 4 and req['body'] == 'null':
                    del req['body']

                if 'body' in req and len(req['body']) or 'body_binary' in req:
                    raise RuntimeError(
                        "Invalid {} {} request: request must not contain a body".format(
                            method, endpoint
                        )
                    )

        elif body.startswith(b'd'):
            raise RuntimeError("Bencoded onion requests not implemented yet")

        else:
            raise RuntimeError(
                "Invalid onion request body: expected JSON object or a bt-encoded dict"
            )

        # Legacy onion request targets don't start with /; we may them to `/target/whatever` (mainly
        # to help organize them here).
        if not endpoint.startswith('/'):
            endpoint = '/legacy/' + endpoint
            if auth_code:
                subreq_headers["Authorization"] = auth_code

        response = make_subrequest(
            method,
            endpoint,
            headers=subreq_headers,
            body=subreq_body,
            content_type=ct,
            user_reauth=True,  # Because onion requests have auth headers on the *inside*
        )

        if response.status_code == http.OK:
            data = response.get_data()
            app.logger.debug(
                f"Onion sub-request for {endpoint} returned success, {len(data)} bytes"
            )
            return data
        return json.dumps({'status_code': response.status_code}).encode()

    except Exception as e:
        app.logger.warning("Invalid onion request: {}".format(e))
        return json.dumps({'status_code': http.BAD_REQUEST}).encode()


@onion_request.post("/oxen/v3/lsrpc")
@onion_request.post("/loki/v3/lsrpc")
def handle_onion_request():
    """
    Parse an onion request, handle it as a subrequest, then encrypt the subrequest result and send
    it back to the requestor.
    """

    try:
        junk = crypto.parse_junk(request.data)
    except RuntimeError as e:
        app.logger.warning("Failed to decrypt onion request: {}".format(e))
        abort(http.INTERNAL_SERVER_ERROR)

    response = handle_onionreq_plaintext(junk.payload)
    return utils.encode_base64(junk.transformReply(response))
