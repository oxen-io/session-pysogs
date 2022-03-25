from ..web import app
from ..model import capabilities
from .. import http
from .. import utils
from .subrequest import make_subrequest

from flask import request, abort, jsonify, Blueprint

# General purpose routes for things like capability retrieval and batching

general = Blueprint('general', __name__)


@general.get("/capabilities")
def get_caps():
    """
    Return the list of server features/capabilities.  Optionally takes a required= parameter
    containing a comma-separated list of capabilites; if any are not satisfied we return a 412
    (Precondition Failed) response with missing requested capabilities in the `missing` key.

    E.g.
    `GET /capabilities` could return `{"capabilities": ["sogs", "batch"]}`
    `GET /capabilities?required=magic,batch` could return:
        `{"capabilities": ["sogs", "batch"], "missing": ["magic"]}`
    """

    res = {'capabilities': sorted(capabilities)}
    needed = request.args.get('required')
    res_code = http.OK
    if needed is not None:
        missing = [cap for cap in needed.split(',') if cap not in capabilities]

        if missing:
            res['missing'] = missing
            res_code = http.PRECONDITION_FAILED

    return jsonify(res), res_code


batch_args = """
    Each individual batch subrequest is a list of dicts containing keys:

    - `method` is required and must be one of GET/DELETE/POST/PUT
    - `path` is required and must begin with a /
    - for POST/PUT requests there must be exactly one of:
        - a json value under the `json` key
        - a base64-encoded body under the `b64` key
        - a raw bytes value under the `bytes` key (not recommended for json)
    - `headers` may be provided, and must be a dict of k/v string pairs if provided.

    If non-conforming data is encountered then the request is terminated with a Bad Request error
    code.
"""


def parse_batch_request(req):
    f"""
    Checks a batch request dict for the required fields.

    {batch_args}

    Returns (method, path, headers, json, body).  `headers` will be a dict (empty if no headers were
    provided); `json`/`body` will be None for GET/DELETE requests; `json` will simply be the `json`
    dict within the request for json bodies, and `body` will be the *bytes* data (i.e. decoded from
    base64, when using `b64`) for 'b64' or 'bytes' requests.
    """
    if not isinstance(req, dict):
        app.logger.warning("Invalid batch request: batch request is not a dict")
        abort(http.BAD_REQUEST)
    if 'method' not in req:
        app.logger.warning("Invalid batch request: batch request has no method")
        abort(http.BAD_REQUEST)
    if 'path' not in req:
        app.logger.warning("Invalid batch request: batch request has no path")
        abort(http.BAD_REQUEST)

    method, path, headers, json, body = req['method'], req['path'], {}, None, None

    if 'headers' in req:
        if not isinstance(req['headers'], dict):
            app.logger.warning("Bad batch request: 'headers' must be a dict")
            abort(http.BAD_REQUEST)
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in req['headers'].items()):
            app.logger.warning("Bad batch request: 'headers' must contain only str/str pairs")
            abort(http.BAD_REQUEST)
        headers = req['headers']

    has_body = method in ('POST', 'PUT')
    if not has_body and method not in ('GET', 'DELETE'):
        app.logger.warning(f"Bad batch request: invalid request method {method}")
        abort(http.BAD_REQUEST)

    if not path.startswith('/'):
        app.logger.warning(f"Bad batch request: path must start with /, got: [{path}]")
        abort(http.BAD_REQUEST)

    n_bodies = sum(k in req for k in ('b64', 'json', 'bytes'))
    if has_body:
        if not n_bodies:
            app.logger.warning(f"Bad batch request: {method} requires one of json/b64/bytes")
            abort(http.BAD_REQUEST)
        elif n_bodies > 1:
            app.logger.warning(
                f"Bad batch request: {method} cannot have more than one of json/bytes/b64"
            )
            abort(http.BAD_REQUEST)

        if 'b64' in req:
            try:
                body = utils.decode_base64(req['b64'])
            except Exception:
                app.logger.warning("Bad batch request: b64 value is not valid base64")
        elif 'bytes' in req:
            body = req['bytes']
            if not isinstance(body, bytes):
                body = body.encode()
        else:
            json = req['json']

    elif n_bodies:
        app.logger.warning(f"Bad batch request: {req['method']} cannot have a json/b64/bytes body")
        abort(http.BAD_REQUEST)

    return method, path, headers, json, body


@general.post("/batch")
def batch(_sequential=False):
    """
    Submits multiple requests wrapped up in a single request, runs them all, then returns the result
    of each one.  Requests are performed independently, that is, if one fails the others will still
    be attempted.  There is no guarantee on the order in which requests will be carried out.  (For
    sequential, related requests invoke via /sequence instead).

    # Body

    {batch_args}

    # Return value

    Returns a list of responses in the same order as the provided requests; each response consists
    of a dict containing:
    - code -- the numeric http response code (e.g. 200 for success)
    - content-type -- the content type of the request
    - body -- the body of the request; will be plain json if `content-type` is `application/json`,
      otherwise it will be base64 encoded data.
    """

    subreqs = request.json
    if not isinstance(subreqs, list):
        abort(http.BAD_REQUEST)

    # Expand this into a list first (rather than during iteration below) so that we abort everything
    # if any subrequest is invalid.
    subreqs = [parse_batch_request(r) for r in subreqs]

    response = []
    for method, path, headers, json, body in subreqs:
        try:
            subres, headers = make_subrequest(method, path, headers=headers, body=body, json=json)
            if subres.content_type == "application/json":
                body = subres.get_json()
            else:
                body = subres.get_data()

            response.append({"code": subres.status_code, "headers": headers, "body": body})
        except Exception as e:
            app.logger.warning(f"Batch subrequest failed: {e}")
            response.append(
                {"code": http.INTERNAL_SERVER_ERROR, 'content-type': 'text/plain', 'body': ''}
            )

        if _sequential and not 200 <= response[-1]['code'] < 300:
            break

    return utils.jsonify_with_base64(response)


@general.post("/sequence")
def sequence():
    """
    This is like batch, except that it guarantees to submit requests sequentially in the order
    provided and stops processing requests if the previous request returned a non-2xx response.

    Like batch, responses are returned in the same order as requests, but unlike batch there may be
    fewer elements in the response list (if requests were stopped because of a non-2xx response).
    In such a case, the final, non-2xx response is still included as the final response value.

    See [`/batch`](#post-batch) for arguments and response.
    """

    return batch(_sequential=True)
