from .. import db, http, utils
from ..model import room as mroom
from ..model.user import User
from ..web import app
from ..omq import omq_global, blueprints_global
from . import omq_auth

from flask import abort, jsonify, g, Blueprint, request

# User-related routes

"""
    TOFIX:
        remove HTTP shit from requests

"""

clients = Blueprint('clients', __name__)
blueprints_global['clients'] = clients


@omq_auth.first_request
def register(cid):
    """
    Registers a client with SOGS OMQ instance. In this context, "client" refers to any entity 
    seeking to create an authenticated OMQ connection. This may be, but is not limited to,
    a user or a bot

    ## URL Parameters

        - 'cid': the client ID (session ID) of the given client to be registered with the SOGS instance

    ## Query Parameters

        - 'bot' (bool) : is bot or not

    ## Body Parameters

    Takes a JSON object as body with the following keys:

        - 'authlevel' : the oxenmq Authlevel to be attributed to the given client
        - 'priority' : the priority level to be assigned to the given bot. If not passed, will be assigned
                        and handled by bot priority-queue
    """

    req = request.json
    bot = utils.get_int_param('bot')    # will set bot == 1 if key "bot" has value True
    authlevel = req.get('authlevel')
    priority = req.get('priority')
    
    client = (bot is 1)[register_client(cid, authlevel),
                        register_bot(cid, authlevel, priority)]

    return client


@clients.post("/client/registered/bot/<cid>")
def register_bot(cid, authlevel, priority):
    """
    Registers a bot with SOGS OMQ instance

    ## URL Parameters

        - 'cid': the client ID (session ID) of the given client to be registered with the SOGS instance

    ## Body Parameters

    Takes a JSON object as body with the following keys (passed as parameters from register()):

        - 'authlevel' : the oxenmq Authlevel to be attributed to the given client
        - 'priority' : the priority level to be assigned to the given bot. If not passed, will be assigned
                        and handled by bot priority-queue
    """

    client = omq_global.send_mule(
        command='register_client',
        cid=cid,
        authlevel=authlevel,
        bot=1,
        priority=priority,
        prefix='handler'
    )

    return client


@clients.post("/client/registered/client/<cid>")
def register_client(cid, authlevel):
    """
    Registers a non-bot client with SOGS OMQ instance

    ## URL Parameters

        - 'cid': the client ID (session ID) of the given client to be registered with the SOGS instance

    ## Body Parameters

    Takes a JSON object as body with the following keys (passed as parameters from register()):

        - 'authlevel' : the oxenmq Authlevel to be attributed to the given client
    """

    client = omq_global.send_mule(
        command='register_client',
        cid=cid,
        authlevel=authlevel,
        bot=0,
        priority=None,
        prefix='handler'
    )

    return client


@omq_auth.admin_required
def unregister(cid):
    """
    Unegisters a non-bot client with SOGS OMQ instance

    ## URL Parameters

        - 'cid': the client ID (session ID) of the given client to be registered with the SOGS instance

    ## Query Parameters

        - 'bot' (bool) : is bot or not
    """
    
    bot = utils.get_int_param('bot')

    client = (bot)[unregister_client(cid), unregister_bot(cid)]

    return client


@clients.post("/client/deregistered/client/<cid>")
@clients.delete("/client/registered/client/<cid>")
def unregister_client(cid):

    client = omq_global.send_mule(
        command='unregister_client',
        cid=cid,
        bot=0,
        prefix='handler'
    )
    
    return client


@clients.post("/bot/deregistered/bot/<cid>")
@clients.delete("/bot/registered/bot/<cid>")
def unregister_bot(cid):
    
    client = omq_global.send_mule(
        command='unregister_bot',
        cid=cid,
        bot=1,
        prefix='handler'
    )

    return client
