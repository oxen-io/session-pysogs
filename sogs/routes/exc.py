from ..web import app
from .. import http
from ..model import exc


# Map uncaught model exceptions into flask http exceptions
@app.errorhandler(exc.NotFound)
def abort_bad_room(e):
    return str(e), http.NOT_FOUND


@app.errorhandler(exc.BadPermission)
def abort_perm_denied(e):
    return str(e), http.FORBIDDEN


@app.errorhandler(exc.PostRejected)
def abort_post_rejected(e):
    return str(e), http.TOO_MANY_REQUESTS


@app.errorhandler(exc.InvalidData)
def abort_invalid_data(e):
    return str(e), http.BAD_REQUEST
