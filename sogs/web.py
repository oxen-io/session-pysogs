import flask

app = flask.Flask(__name__)

# Monkey-patch app.get/post/etc. for Flask <2 compatibility; this has to be before the imports,
# below, because they depend on this existing.
if not hasattr(flask.Flask, 'post'):

    def _add_flask_method(name):
        def meth(self, rule: str, **options):
            return self.route(rule, methods=[name.upper()], **options)

        setattr(flask.Flask, name, meth)

    for method in ('get', 'post', 'put', 'delete', 'patch'):
        _add_flask_method(method)

from . import logging  # noqa: F401, E402
from . import routes  # noqa: F401, E402
from . import onion_request  # noqa: F401, E402
from . import legacy_routes  # noqa: F401, E402
from . import cleanup  # noqa: F401, E402
from . import model  # noqa: E402
from . import http  # noqa: E402


# Map uncaught model exceptions into flask http exceptions
@app.errorhandler(model.NotFound)
def abort_bad_room(e):
    flask.abort(http.NOT_FOUND)


@app.errorhandler(model.BadPermission)
def abort_perm_denied(e):
    flask.abort(http.FORBIDDEN)


@app.errorhandler(model.PostRejected)
def abort_post_rejected(e):
    flask.abort(http.TOO_MANY_REQUESTS)
