import traceback
import oxenmq
from oxenc import bt_deserialize
import time
from datetime import timedelta
import functools

from .web import app
from . import cleanup
from . import config
from . import omq as o

# This is the uwsgi "mule" that handles things not related to serving HTTP requests:
# - it holds the oxenmq instance (with its own interface into sogs)
# - it handles cleanup jobs (e.g. periodic deletions)


def run():
    try:
        app.logger.info("OxenMQ mule started.")

        while True:
            time.sleep(1)

    except Exception:
        app.logger.error("mule died via exception:\n{}".format(traceback.format_exc()))


def allow_conn(addr, pk, sn):
    # TODO: user recognition auth
    return oxenmq.AuthLevel.basic


def admin_conn(addr, pk, sn):
    return oxenmq.AuthLevel.admin


def inproc_fail(connid, reason):
    raise RuntimeError(f"Couldn't connect mule to itself: {reason}")


def setup_omq():
    omq = o.omq

    app.logger.debug("Mule setting up omq")
    if isinstance(config.OMQ_LISTEN, list):
        listen = config.OMQ_LISTEN
    elif config.OMQ_LISTEN is None:
        listen = []
    else:
        listen = [config.OMQ_LISTEN]
    for addr in listen:
        omq.listen(addr, curve=True, allow_connection=allow_conn)
        app.logger.info(f"OxenMQ listening on {addr}")

    # Internal socket for workers to talk to us:
    omq.listen(config.OMQ_INTERNAL, curve=False, allow_connection=admin_conn)

    # Periodic database cleanup timer:
    omq.add_timer(cleanup.cleanup, timedelta(seconds=cleanup.INTERVAL))

    # Commands other workers can send to us, e.g. for notifications of activity for us to know about
    worker = omq.add_category("worker", access_level=oxenmq.AuthLevel.admin)
    worker.add_command("message_posted", message_posted)
    worker.add_command("messages_deleted", messages_deleted)
    worker.add_command("message_edited", message_edited)

    app.logger.debug("Mule starting omq")
    omq.start()

    # Connect mule to itself so that if something the mule does wants to send something to the mule
    # it will work.  (And so be careful not to recurse!)
    app.logger.debug("Mule connecting to self")
    o.mule_conn = omq.connect_inproc(on_success=None, on_failure=inproc_fail)


def log_exceptions(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"{f.__name__} raised exception: {e}")
            raise

    return wrapper


@log_exceptions
def message_posted(m: oxenmq.Message):
    id = bt_deserialize(m.data()[0])
    app.logger.warning(f"FIXME: mule -- message posted stub, id={id}")


@log_exceptions
def messages_deleted(m: oxenmq.Message):
    ids = bt_deserialize(m.data()[0])
    app.logger.warning(f"FIXME: mule -- message delete stub, deleted messages: {ids}")


@log_exceptions
def message_edited(m: oxenmq.Message):
    app.logger.warning("FIXME: mule -- message edited stub")
