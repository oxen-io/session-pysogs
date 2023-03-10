import oxenmq
import auth
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

# Authentication for handling OMQ requests


def abort_request(code, msg, warn=True):
    if warn:
        app.logger.warning(msg)
    else:
        app.logger.debug(msg)
    abort(Response(msg, status=code, mimetype='text/plain'))


def require_client():
    """ Requires that an authenticated client was found in the OMQ instance; aborts with 
    UNAUTHORIZED if the request has no client """
    if g.client_id is None:
        abort_request(http.UNAUTHORIZED, 'OMQ client authentication required')


def client_required(f):
    """ Decorator for an endpoint that requires a client; this calls require_client() at the 
    beginning of the request to abort the request as UNAUTHORIZED if the client has not been 
    previously authenticated"""

    @wraps(f)
    def required_client_wrapper(*args, **kwargs):
        require_client()
        return f(*args, **kwargs)
    
    return required_client_wrapper


def require_authlevel(admin=True):
    require_client()
    if g.client_authlevel is not oxenmq.Authlevel.admin if admin else g.client_authlevel is not oxenmq.Authlevel.basic:
        abort_request(
            http.FORBIDDEN, 
            f"This endpoint requires oxenmq.Authlevel.{'admin' if admin else 'basic'} permissions"
        )


def basic_required(f):
    """ Decorator for an endpoint that requires a client has basic OMQ authorization """

    @wraps(f)
    def required_basic_wrapper(*args, **kwargs):
        require_authlevel(admin=False)
        return f(*args, **kwargs)
    
    return required_basic_wrapper


def admin_required(f):
    """ Decorator for an endpoint that requires a client has admin OMQ authorization """

    @wraps(f)
    def required_admin_wrapper(*args, **kwargs):
        require_authlevel(admin=True)
        return f(*args, **kwargs)
    
    return required_admin_wrapper


def first_request(f):
    """ Decorator for an endpoint that will be the very first request for a given client. This 
    will ensure that the client is then registered for any subsequent requests.
    
    This function will typically take the folling parameters:
        - cid : unique client ID to be attributed
        - authlevel (oxenmq)
    """

    @wraps
    def first_request_wrapper(*args, cid, authlevel, **kwargs):
        handle_omq_registration(cid, authlevel)
        return f(*args, cid=cid, authlevel=authlevel, **kwargs)
    
    return first_request_wrapper


def handle_omq_registration(sid, authlevel):
    """
    Registers client with OMQ instance before its very first request
    """
    if hasattr(g, 'client_id') and hasattr(g, 'client_authlevel') and not g.client_reauth:
        app.logger.warning(f"Client {g.client_id} already registered for {g.client_authlevel} access")
        return
    
    """
    Here goes ye olde OMQ registration logic. We need to decide what identification will
    be used to verify every connected client s.t. that information persists for all subsequent
    requests.

    In this registration, we need to set:
        g.client_id
        g.client_authlevel
    """


@app.before_request
def verify_omq_auth():
    """
    Verifies OMQ authentication before each request
    """
    
    # If there is already a g.o_id, then this is NOT the first request made by this client, unless
    # g.client_reauth has been specifically set
    if hasattr(g, 'client_id') and hasattr(g, 'client_authlevel') and not g.client_reauth:
        app.logger.debug(f"Client {g.client_id} already authenticated for {g.client_authlevel} access")
        return
