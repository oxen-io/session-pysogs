from ..web import app
from ..model import capabilities
from .. import http

from flask import request

# General purpose routes for things like capability retrieval and batching


@app.get("/capabilities")
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
