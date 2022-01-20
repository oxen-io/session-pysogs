from ..web import app
from .. import http

from flask import request, g
from io import BytesIO
import traceback
from typing import Optional, Union


def make_subrequest(
    method: str,
    path: str,
    *,
    headers={},
    content_type: Optional[str] = None,
    body: Optional[bytes] = None,
    json: Optional[Union[dict, list]] = None,
    user_reauth: bool = False,
):
    """
    Makes a subrequest from the given parameters, returns the response object.

    Parameters:
    method - the HTTP method, e.g. GET or POST
    path - the request path (optionally including a query string)
    headers - dict of HTTP headers for the request
    content_type - the content-type of the request (for POST/PUT methods)
    body - the bytes content of the body of a POST/PUT method.  If specified then content_type will
    default to 'application/octet-stream'.
    json - a json value to dump as the body of the request.  If specified then content_type will
    default to 'applicaton/json'.
    user_reauth - if True then we allow user re-authentication on the subrequest based on its
    X-SOGS-* headers; if False (the default) then the user auth on the outer request is preserved
    (even if it was None) and inner request auth headers will be ignored.
    """

    http_headers = {'HTTP_{}'.format(h.upper().replace('-', '_')): v for h, v in headers.items()}

    if content_type is None:
        if 'HTTP_CONTENT_TYPE' in http_headers:
            content_type = http_headers['HTTP_CONTENT_TYPE']
        elif body is not None:
            content_type = 'application/octet-stream'
        elif json is not None:
            content_type = 'application/json'
        else:
            content_type = ''

    for x in ('HTTP_CONTENT_TYPE', 'HTTP_CONTENT_LENGTH'):
        if x in http_headers:
            del http_headers[x]

    if body is None:
        if json is not None:
            from json import dumps

            body = dumps(json, separators=(',', ':')).encode()
        else:
            body = b''

    body_input = BytesIO(body)
    content_length = len(body)

    if '?' in path:
        path, query_string = path.split('?', 1)
    else:
        query_string = ''

    # Set up the wsgi environ variables for the subrequest (see PEP 0333)
    subreq_env = {
        **request.environ,
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": content_length,
        **http_headers,
        'wsgi.input': body_input,
        'flask._preserve_context': False,
    }

    try:
        app.logger.debug(f"Initiating sub-request for {method} {path}")
        g.user_reauth = user_reauth
        with app.request_context(subreq_env):
            response = app.full_dispatch_request()
        if response.status_code != http.OK:
            app.logger.warning(
                f"Sub-request for {method} {path} returned status {response.status_code}"
            )
        return response
    except Exception:
        app.logger.warning(f"Sub-request for {method} {path} failed: {traceback.format_exc()}")
        raise
