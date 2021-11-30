import uwsgi
import traceback
import oxenmq
from datetime import timedelta

from .web import app
from .signal import Signal
from . import cleanup
from . import config
from . import crypto

# This is the uwsgi "mule" that handles things not related to serving HTTP requests:
# - it holds the oxenmq instance (with its own interface into sogs)
# - it handles cleanup jobs (e.g. periodic deletions)

omq = None


def run():
    if uwsgi.mule_id() != 1:
        app.logger.critical(
            "Error: sogs.mule must be the first uwsgi mule (mule1), not mule{}".format(
                uwsgi.mule_id()
            )
        )
        raise RuntimeError("Invalid uwsgi configuration")

    try:
        setup_omq()

        run_loop()
    except:
        app.logger.error("mule died via exception:\n{}".format(traceback.format_exc()))


def allow_conn(addr, pk, sn):
    # TODO: user recognition auth
    return oxenmq.AuthLevel.basic


def setup_omq():
    global omq
    omq = oxenmq.OxenMQ(
        privkey=crypto._privkey.encode(),
        pubkey=crypto.server_pubkey.encode(),
        log_level=oxenmq.LogLevel.fatal,
    )
    if isinstance(config.OMQ_LISTEN, list):
        listen = config.OMQ_LISTEN
    elif config.OMQ_LISTEN is None:
        listen = []
    else:
        listen = [config.OMQ_LISTEN]
    for addr in listen:
        omq.listen(addr, curve=True, allow_connection=allow_conn)
        app.logger.info(f"OxenMQ listening on {addr}")
    omq.add_timer(cleanup.cleanup, timedelta(seconds=cleanup.INTERVAL))
    omq.start()


def run_loop():
    app.logger.info("mule started!")

    callbacks = {Signal.MESSAGE_POSTED: message_posted, Signal.MESSAGE_DELETED: message_deleted}

    app.logger.info("mule started 2!")
    while True:
        app.logger.info("mule started looping")
        msg = uwsgi.mule_get_msg()
        app.logger.info("mule ax {}".format(msg))
        try:
            sig = Signal(int(msg.decode()))
        except ValueError:
            app.logger.error(f"mule received unregistered uwsgi mule message {msg}")
            continue

        if sig in callbacks:
            try:
                callbacks[sig]()
            except Exception as e:
                app.logger.error(
                    f"An exception occured while mule was processing uwsgi signal {sig}:\n{e}"
                )
        else:
            app.logger.error(f"mule received uwsgi signal {sig} but that signal has no handler!")
    app.logger.info("mule done")


def message_posted():
    app.logger.warning("FIXME: mule -- message posted stub")


def message_deleted():
    app.logger.warning("FIXME: mule -- message delete stub")
