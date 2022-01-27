from collections import defaultdict

from oxenmq import AuthLevel

from . import model
from .omq import omq
from .web import app

from binascii import hexlify
from types import Iterable

from oxenc import bt_serialize

from .routes.subrequest import make_subrequest

from flask import g

# pools for event propagation
_pools = defaultdict(list)

status_OK = 'OK'
status_ERR = 'ERROR'

# the events we are able to subscribe to
EVENTS = ('message', 'joined', 'parted', 'banned', 'unbanned', 'deleted', 'uploaded')


def event_name_valid(eventname):
    """ return True if this event name is something well formed """
    return eventname in EVENTS


def _user_from_conn(conn):
    """
    make a model.User from a connection using it's curve pubkey as the session id.
    """
    return model.User(session_id='05' + hexlify(conn.pubkey).decode())


def _maybe_serialize(data):
    """maybe bt encode data, if data is a bytes dont encode,
    if data is a string turn it into bytes and dont encode, otherwise bt encode"""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return bt_serialize(data)


def _propagate_event(eventname, *args):
    """ propagate an event to everyone who cares about it """
    assert event_name_valid(eventname)
    global omq, _pools
    sent = 0
    for conn in _pools[eventname]:
        omq.send(conn, f'sogs.event.{eventname}', *(_maybe_serialize(a) for a in args))
        sent += 1
    if sent:
        app.logger.info(f"sent {eventname} to {sent} subscribers")


_category = omq.add_category('sogs', AuthLevel.basic)


def api(f, *, name=None, minargs=None):
    """ set up a request handler for zmq for a function with name of the endpoint """
    assert name is not None

    def _handle_request(msg):
        try:
            if minargs and len(msg.data) < minargs:
                raise ValueError(f"Not enough arguments, got {len(msg.data)} expected 2 or more")
            app.logger.debug(f"zmq request: {name} for {msg.conn}")
            g.user = _user_from_conn(msg.conn)
            retval = f(*msg.data, conn=msg.conn)
            if retval is None:
                msg.reply(status_OK)
            elif isinstance(retval, tuple):
                msg.reply(status_OK, *retval)
            else:
                msg.reply(status_OK, bt_serialize(retval))
        except Exception as ex:
            app.logger.error(f"{f.__name__} raised exception: {ex}")
            msg.reply(status_ERR, f'{ex}')
        finally:
            g.user = None

    global _category
    _category.add_request_command(name, _handle_request)
    app.logger.info(f"register zmq api handler: sogs.{name}")
    return f


def _collect_bytes(iterable: Iterable[bytes]):
    """ collect all bytes from an iterable of bytes and put it into one big bytes instance """
    data = bytes()
    for part in iterable:
        data += part
    return data


@api(name='sub', minargs=1)
def handle_subscribe(*events, conn=None):
    """ subscribe connection to many events """
    sub = set()
    for ev in events:
        name = ev.decode('ascii')
        if not event_name_valid(name):
            raise Exception(f"invalid event type: {name}")
        sub += name

    global _pools
    for name in sub:
        _pools[name].append(conn)
    app.logger.debug(f"sub {conn} to {len(sub)} events")


@api(name='unsub', minargs=1)
def handle_unsubscribe(*events, conn=None):
    """ unsub connection to many events """
    unsub = set()
    for ev in events:
        name = ev.decode('ascii')
        if not event_name_valid(name):
            raise Exception(f"invalid event type: {name}")
        unsub += name

    global _pools
    for name in unsub:
        _pools[name].remove(conn)
    app.logger.debug(f"unsub {conn} to {len(unsub)} events")


@api(name="request", minargs=2)
def handle_rpc_call(method, path, body=None, *, conn=None):
    """ make a sub request via zmq """
    ctype = None
    # guess content type
    if body:
        if body[0] in (b'{', b'['):
            ctype = 'application/json'
        else:
            ctype = 'application/octet-stream'

    resp = make_subrequest(
        method.decode('ascii'), path.decode('ascii'), content_type=ctype, body=body
    )
    return resp.status_code, _collect_bytes(resp.response)


class _Notify:
    """ Holder type for all event notification functions """


notify = _Notify()

# set up event notifiers
for ev in EVENTS:
    setattr(notify, ev, lambda *args: _propagate_event(ev, *args))
