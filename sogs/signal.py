from enum import Enum
import logging


class Signal(Enum):
    """
    UWSGI control signals we use to control the mule process.  These are used to wake up the mule to
    respond to updates in the database that may need further action, for example to notify connected
    oxenmq clients of an event.
    """

    # Signals for the mule.  The values don't matter, as long as they are unique integers

    MESSAGE_POSTED = 1  # A new message has been inserted in the database
    MESSAGE_DELETED = 2  # A message has been deleted from the database
    MESSAGE_EDITED = 3  # A message has been edited


try:
    import uwsgi

    _send_msg = uwsgi.mule_msg
except ModuleNotFoundError:
    logging.error("uwsgi not available; signals disabled")
    _send_msg = None


def send_signal(sig: Signal):
    """
    Sends the given signal to the mule.  If uwsgi is not available then this does nothing.
    """

    if _send_msg is not None:
        _send_msg("{}".format(sig.value).encode(), 1)
