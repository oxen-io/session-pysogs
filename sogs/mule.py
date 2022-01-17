import traceback
import oxenmq
import time
from datetime import timedelta
import functools

from .web import app
from . import cleanup
from . import config
from . import omq as o
from .events import notify

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
    if not listen:
        app.logger.warn(
            "OxenMQ did not listen on any curve addresses, the bot API is not accessable anywhere."
        )

    # Internal socket for workers to talk to us:
    omq.listen(config.OMQ_INTERNAL, curve=False, allow_connection=admin_conn)

    # Periodic database cleanup timer:
    omq.add_timer(cleanup.cleanup, timedelta(seconds=cleanup.INTERVAL))

    # Commands other workers can send to us, e.g. for notifications of activity for us to know about
    worker = omq.add_category("worker", access_level=oxenmq.AuthLevel.admin)
    worker.add_command("message_posted", message_posted)
    worker.add_command("messages_deleted", messages_deleted)
    worker.add_command("message_edited", message_edited)
    worker.add_command("user_joined", user_joined)
    worker.add_command("user_banned", user_banned)
    worker.add_command("user_unbanned", user_unbanned)
    worker.add_command("file_uploaded", file_uploaded)

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
    notify.message(*m.data())


@log_exceptions
def messages_deleted(m: oxenmq.Message):
    notify.deleted(*m.data())


@log_exceptions
def user_banned(m: oxenmq.Message):
    notify.banned(*m.data())


@log_exceptions
def user_unbanned(m: oxenmq.Message):
    notify.unbannd(*m.data())


@log_exceptions
def user_joined(m: oxenmq.Message):
    notify.joined(*m.data())


@log_exceptions
def file_uploaded(m: oxenmq.Message):
    notify.uploaded(*m.data())


@log_exceptions
def message_edited(m: oxenmq.Message):
    app.logger.warning("FIXME: mule -- message edited stub")
