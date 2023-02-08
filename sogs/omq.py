# Common oxenmq object; this is used by workers and the oxenmq mule.  We create, but do not start,
# this pre-forking.

import oxenmq
from oxenc import bt_serialize

from . import crypto, config
from .postfork import postfork
from .model.manager import Manager

omq_global = None

class OMQ:
    @postfork
    def __init__(self):
        try:
            import uwsgi
        except ModuleNotFoundError:
            return

        self._omq = oxenmq.OxenMQ(
            privkey=crypto._privkey.encode(), pubkey=crypto.server_pubkey.encode()
        )
        self._omq.ephemeral_routing_id = True

        self.manager = Manager()
        self.test_suite = False

        if uwsgi.mule_id() != 0:
            uwsgi.opt['mule'].setup_omq(self)
            return

        from .web import app  # Imported here to avoid circular import

        app.logger.debug(f"Starting oxenmq connection to mule in worker {uwsgi.worker_id()}")

        self._omq.start()
        app.logger.debug("Started, connecting to mule")
        self.mule_conn = self._omq.connect_remote(oxenmq.Address(config.OMQ_INTERNAL))

        app.logger.debug(f"worker {uwsgi.worker_id()} connected to mule OMQ")

        global omq_global
        omq_global = self

    def add_bot(self):
        self.manager.add_bot()
        # TODO: add omq logic

    def remove_bot(self):
        self.manager.remove_bot()
        # TODO: add omq logic

    def send_mule(self, command, *args, prefix="worker."):
        """
        Sends a command to the mule from a worker (or possibly from the mule itself).  The command will
        be prefixed with "worker." (unless overridden).

        Any args will be bt-serialized and send as message parts.
        """
        
        if prefix:
            command = prefix + command

        if self.test_suite and self._omq is None:
            pass  # TODO: for mule call testing we may want to do something else here?
        else:
            self._omq.send(self.mule_conn, command, *(bt_serialize(data) for data in args))
