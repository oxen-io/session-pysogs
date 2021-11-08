from flask import request, abort
import json
from io import BytesIO

from .web import app
from . import http
from . import crypto
from . import utils

import traceback


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
                cl = len(subreq_body)
            else:
                subreq_body = b''
                # Android bug workaround: Android Session (at least up to v1.11.12) sends a body on
                # GET requests with a 4-character string "null" when it should send no body.
                if 'body' in req and len(req['body']) == 4 and req['body'] == 'null':
                    del req['body']

                if 'body' in req and len(req['body']) or 'body_binary' in req:
                    raise RuntimeError(
                        "Invalid {} {} request: request must not contain a body".format(method, endpoint)
                    )
                ct, cl = '', ''

            for h in ('content-type', 'content-length'):
                if h in subreq_headers:
                    del subreq_headers[h]

        elif body.startswith(b'd'):
            raise RuntimeError("Bencoded onion requests not implemented yet")

        else:
            raise RuntimeError(
                "Invalid onion request body: expected JSON object or a bt-encoded dict"
            )

        if '?' in endpoint:
            endpoint, query_string = endpoint.split('?', 1)
        else:
            query_string = ''

        # Legacy onion request targets don't start with /; we may them to `/target/whatever` (mainly
        # to help organize them here).
        if not endpoint.startswith('/'):
            endpoint = '/legacy/' + endpoint
            if auth_code:
                subreq_headers["Authorization"] = auth_code
        # Set up the wsgi environ variables for the subrequest (see PEP 0333)
        subreq_env = {
            **request.environ,
            "REQUEST_METHOD": method,
            "PATH_INFO": endpoint,
            "QUERY_STRING": query_string,
            "CONTENT_TYPE": ct,
            "CONTENT_LENGTH": cl,
            **{'HTTP_{}'.format(h.upper().replace('-', '_')): v for h, v in subreq_headers.items()},
            'wsgi.input': BytesIO(subreq_body),
        }

        try:
            with app.request_context(subreq_env):
                response = app.full_dispatch_request()
            if response.status_code == 200:
                data = response.get_data()
                app.logger.debug("Onion sub-request returned success, {} bytes".format(len(data)))
                return data
            app.logger.warn(
                "Onion sub-request for {} {} returned status {}".format(
                    method, endpoint, response.status_code
                )
            )
            return json.dumps({'status_code': response.status_code}).encode()
        except Exception as e:
            app.logger.warn(
                "Onion sub-request for {} {} failed: {}".format(
                    method, endpoint, traceback.format_exc()
                )
            )
            return json.dumps({'status_code': http.BAD_GATEWAY}).encode()
    except Exception as e:
        app.logger.warn("Invalid onion request: {}".format(e))
        return json.dumps({'status_code': http.BAD_REQUEST}).encode()


@app.post("/oxen/v3/lsrpc")
@app.post("/loki/v3/lsrpc")
def handle_onion_request():
    """
    Parse an onion request, handle it as a subrequest, then encrypt the subrequest result and send
    it back to the requestor.
    """

    try:
        junk = crypto.parse_junk(request.data)
    except RuntimeError as e:
        app.logger.warn("Failed to decrypt onion request: {}".format(e))
        abort(http.ERROR_INTERNAL_SERVER_ERROR)

    response = handle_onionreq_plaintext(junk.payload)
    return utils.encode_base64(junk.transformReply(response))
