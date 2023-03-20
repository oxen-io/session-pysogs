from flask import request, abort, Blueprint
from nacl.utils import random
import oxenmq
import json

from ..web import app
from .. import crypto, http, utils

from .omq_subrequest import make_omq_subreq


def handle_v4onion_omqreq_plaintext(msg: oxenmq.Message):
    """
    Handles a decrypted v4 onion request; this injects a subrequest to process it then returns the
    result of that subrequest.  In contrast to v3, it is more efficient (particularly for binary
    input or output) and allows using endpoints that return headers or bodies with non-2xx response
    codes.

    Message (request) components:

    "endpoint" - the omq endpoint
    "query" - the request query
    "pubkey" - pk of client making request
    "params" - a json value to dump as the the query parameters

        Example:
            full request: `omq.endpoint('some_endpoint', 'room.messages_since', jvi0grsj3029fjwhatever, {'Room:room', 'int:seqno'})`
                endpoint: 'some_endpoint'
                query: 'room.messages_since'
                pubkey: jvi0grsj3029fjwhatever
                params: {'Room:room', 'int:seqno'}
    """

    try:
        body = msg.data()[0]

        if not (body.startswith(b'l') and body.endswith(b'e')):
            raise RuntimeError("Invalid onion request body: expected bencoded list")

        args = json.loads(body)

        subreq_id = random(16)
        endpoint = args['endpoint']
        query = args['query']
        pubkey = utils.decode_hex_or_b64(args['pubkey'], 33)
        params = args['params']

        response = make_omq_subreq(
            subreq_id,
            endpoint,
            query,
            pubkey,
            msg.later(),
            params,
            client_reauth=True,  # Because onion requests have auth headers on the *inside*
        )

        data = response.get_data()
        app.logger.debug(
            f"Onion sub-request for {endpoint} returned {response.status_code}, {len(data)} bytes"
        )

        args = {'code': response.status_code, 'headers': headers}

    except Exception as e:
        app.logger.warning("Invalid v4 onion request: {}".format(e))
        args = {'code': http.BAD_REQUEST, 'headers': {'content-type': 'text/plain; charset=utf-8'}}
        data = b'Invalid v4 onion request'

    args = json.dumps(args).encode()
    return b''.join(
        (b'l', str(len(args)).encode(), b':', args, str(len(data)).encode(), b':', data, b'e')
    )


def decrypt_onionreq():
    try:
        return crypto.parse_junk(request.data)
    except Exception as e:
        app.logger.warning("Failed to decrypt onion request: {}".format(e))
    abort(http.BAD_REQUEST)


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
        junk = crypto.parse_junk(request.data)
    except RuntimeError as e:
        app.logger.warning("Failed to decrypt onion request: {}".format(e))
        abort(http.BAD_REQUEST)

    # On the way back out we re-encrypt via the junk parser (which uses the ephemeral key and
    # enc_type that were specified in the outer request).  We then return that encrypted binary
    # payload as-is back to the client which bounces its way through the SN path back to the client.
    response = handle_v4onion_omqreq_plaintext(junk.payload)
    return junk.transformReply(response)
