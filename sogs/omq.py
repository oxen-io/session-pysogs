# Common oxenmq object; this is used by workers and the oxenmq mule.  We create, but do not start,
# this pre-forking.

import oxenmq, queue
from oxenc import bt_serialize, bt_deserialize

from mule import log_exceptions
from routes import omq_auth
from . import crypto, config
from .postfork import postfork
from .model.clientmanager import ClientManager


omq_global = None
global blueprints_global
blueprints_global = {}


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
        self.client_map = {}
        self.manager = ClientManager()
        self.test_suite = False
        self.subreq_queue = queue.SimpleQueue()

        if uwsgi.mule_id() != 0:
            uwsgi.opt['mule'].setup_omq(self)
            return
        
        uwsgi.register_signal(123, 'internal', self.handle_proxied_omq_req)

        from .web import app  # Imported here to avoid circular import

        app.logger.debug(f"Starting oxenmq connection to mule in worker {uwsgi.worker_id()}...")
        self._omq.start()

        app.logger.debug("Started, connecting to mule...")
        self.mule_conn = self._omq.connect_remote(oxenmq.Address(config.OMQ_INTERNAL))

        app.logger.debug(f"OMQ worker {uwsgi.worker_id()} connected to mule")

        global omq_global
        omq_global = self

    
    @log_exceptions
    def subreq_response(self):
        pass


    @log_exceptions
    def handle_proxied_omq_req(self):
        id, subreq_body = self.send_mule(
            command='get_next_request',
            prefix='internal'
        )

        '''
            
            Handle omq subrequest

        '''

        return 

    @log_exceptions
    def get_next_request(self):
        subreq_body = self.subreq_queue.get()
        id = list(subreq_body.keys())[0]
        return id, subreq_body[id]


    @log_exceptions
    def register_client(self, msg: oxenmq.Message):
        cid, authlevel, bot, priority = bt_deserialize(msg.data()[0])
        conn_id = msg.conn()
        self.client_map[conn_id] = cid
        self.manager.register_client(msg)


    @log_exceptions
    def deregister_client(self, msg: oxenmq.Message):
        cid, bot = bt_deserialize(msg.data()[0])
        self.client_map.pop(cid)
        self.manager.deregister_client(cid, bot)


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
