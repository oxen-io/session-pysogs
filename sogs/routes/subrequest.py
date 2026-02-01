from ..web import app

from flask import request, g
from io import BytesIO
import traceback
from typing import Optional, Union
import urllib.parse


def make_subrequest(
    method: str,
    path: str,
    *,
    headers={},
    content_type: Optional[str] = None,
    body: Optional[Union[bytes, memoryview]] = None,
    json: Optional[Union[dict, list]] = None,
    user_reauth: bool = False,
):
    """
    Makes a subrequest from the given parameters, returns the response object and a dict of
    lower-case response headers keys to header values.

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

    if '%' in path:
        path = urllib.parse.unquote(path, errors='strict')

    # Werkzeug has some screwy internals: it requires PATH_INFO to be a bastardized string
    # masquerading as bytes: it encodes the string as latin1, then decodes *those* bytes to utf-8.
    # So we have to muck around here to get our unicode as utf-8 bytes then shove those into a
    # latin1 string.  WTF.
    monkey_path = path
    if any(ord(c) > 127 for c in path):
        monkey_path = path.encode('utf-8').decode('latin1')

    # Set up the wsgi environ variables for the subrequest (see PEP 0333)
    subreq_env = {
        **request.environ,
        "REQUEST_METHOD": method,
        "PATH_INFO": monkey_path,
        "QUERY_STRING": query_string,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(content_length),
        **http_headers,
        'wsgi.input': body_input,
        'flask._preserve_context': False,
    }
    try:
        app.logger.debug(f"Initiating sub-request for {method} {path}")
        g.user_reauth = user_reauth
        with app.request_context(subreq_env):
            try:
                response = app.full_dispatch_request()
            except Exception as e:
                response = app.make_response(app.handle_exception(e))
        if response.status_code >= 400:
            app.logger.warning(
                f"Sub-request for {method} {path} returned status {response.status_code}"
            )
        return (
            response,
            {
                k.lower(): v
                for k, v in response.get_wsgi_headers(subreq_env)
                if k.lower() != 'content-length'
            },
        )

    except Exception:
        app.logger.warning(f"Sub-request for {method} {path} failed: {traceback.format_exc()}")
        raise
