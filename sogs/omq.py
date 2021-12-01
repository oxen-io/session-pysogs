# Common oxenmq object; this is used by workers and the oxenmq mule.  We create, but do not start,
# this pre-forking.

import oxenmq
from oxenc import bt_serialize

from . import crypto, config
from .postfork import postfork

omq = None
mule_conn = None


def make_omq():
    omq = oxenmq.OxenMQ(privkey=crypto._privkey.encode(), pubkey=crypto.server_pubkey.encode())

    # We have multiple workers talking to the mule, so we *must* use ephemeral ids to not replace each
    # others' connections.
    omq.ephemeral_routing_id = True

    return omq


# Postfork for workers: we start oxenmq and connect to the mule process
@postfork
def start_oxenmq():
    try:
        import uwsgi
    except ModuleNotFoundError:
        return

    global omq, mule_conn

    omq = make_omq()

    if uwsgi.mule_id() != 0:
        from . import mule

        mule.setup_omq()
        return

    from .web import app  # Imported here to avoid circular import

    app.logger.debug(f"Starting oxenmq connection to mule in worker {uwsgi.worker_id()}")

    omq.start()
    app.logger.debug(f"Started, connecting to mule")
    mule_conn = omq.connect_remote(oxenmq.Address(config.OMQ_INTERNAL))

    app.logger.debug(f"worker {uwsgi.worker_id()} connected to mule OMQ")


def send_mule(command, *args, prefix="worker."):
    """
    Sends a command to the mule from a worker (or possibly from the mule itself).  The command will
    be prefixed with "worker." (unless overridden).

    Any args will be bt-serialized and send as message parts.
    """
    if prefix:
        command = prefix + command

    omq.send(mule_conn, command, *(bt_serialize(data) for data in args))
