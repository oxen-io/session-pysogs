import flask
from werkzeug.local import LocalProxy
from . import config
import coloredlogs

app = flask.Flask(__name__, template_folder=config.TEMPLATE_PATH, static_folder=config.STATIC_PATH)
coloredlogs.install(milliseconds=True, isatty=True, logger=app.logger, level=config.LOG_LEVEL)

# Monkey-patch app.get/post/etc. for Flask <2 compatibility; this has to be before the imports,
# below, because they depend on this existing.
if not hasattr(flask.Flask, 'post'):

    def _add_flask_method(name):
        def meth(self, rule: str, **options):
            return self.route(rule, methods=[name.upper()], **options)

        setattr(flask.Flask, name, meth)

    for method in ('get', 'post', 'put', 'delete', 'patch'):
        _add_flask_method(method)


def get_db_conn():
    if 'conn' not in flask.g:
        from . import db

        flask.g.conn = db.get_conn()

    return flask.g.conn


@app.teardown_appcontext
def teardown_db_conn(exception):
    conn = flask.g.pop('conn', None)

    if conn is not None:
        conn.close()


# An application-context, lazily evaluated database connection.  (Note that in some contexts, such
# as __main__.py, we may have replaced this with a non-lazy, actual current connection).
appdb = LocalProxy(get_db_conn)


from . import routes
from . import onion_request
from . import legacy_routes
from . import cleanup
