from ..web import app
from ..omq import omq_global

from flask import request, g
from io import BytesIO
from typing import Optional, Union
import traceback, json, urllib.parse, oxenmq


def make_omq_subreq(
    subreq_id,
    endpoint: str,
    query: str,
    pubkey,
    msg_later: oxenmq.Message.send_later,
    params: Optional[Union[dict, list]] = None,
    client_reauth: bool = False,
):
    """
    Makes an omq subrequest from the given parameters, returns the response object and a dict of
    lower-case response headers keys to header values

    Parameters:
    subreq_id - randomly generated ID for subrequest
    endpoint - the flask blueprint/endpoint to be queried
    query - the callable module method in format <route>.<callable_func>
    pubkey - pk of client making request
    msg_later - &oxenmq::Message::DeferredSend reference to be stored in subreq_queue along with data
    params - a json value to dump as the the query parameters
    """

    if params is not None:
        body = json.dumps(params, separators=(',', ':')).encode()
    else:
        body = b''

    body_input = BytesIO(body)
    content_length = len(body)

    subreq_body = {
        subreq_id: {
            'endpoint': endpoint,
            'query': query,
            'pubkey': pubkey,
            'msg_later': msg_later,
            'params': params,
        }
    }

    try:
        app.logger.debug(f"Injecting sub-request for omq.{endpoint} {query}")
        g.client_reauth = client_reauth

        omq_global.subreq_queue.put(subreq_body)

        try:
            import uwsgi
        except ModuleNotFoundError:
            return

        uwsgi.signal(123)

    except Exception:
        app.logger.warning(
            f"Sub-request for omq.{endpoint} {query} failed: {traceback.format_exc()}"
        )
        raise
