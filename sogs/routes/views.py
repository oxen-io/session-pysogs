from flask import abort, render_template, Response, Blueprint

from .. import config, crypto, http
from ..model.room import get_accessible_rooms
from . import auth, converters  # noqa: F401
from ..omq import omq_global
from ..web import app


from io import BytesIO

import qrcode

import PIL.Image

if hasattr(PIL.Image, 'Resampling'):
    NEAREST = PIL.Image.Resampling.NEAREST
else:
    NEAREST = PIL.Image.NEAREST


views = Blueprint('views', __name__)
app.register_blueprint(views)


@views.get("/")
def serve_index():
    """
    Publicly accessible URL that displays a list of public rooms to a web browser.  This isn't a
    normal SOGS client endpoint, but rather a convenience web page for people who follow a SOGS
    pseudo-URL.
    """
    rooms = get_accessible_rooms()
    if len(rooms) == 0:
        return render_template('setup.html')
    if not config.HTTP_SHOW_INDEX:
        abort(http.FORBIDDEN)
    return render_template(
        "index.html", url_base=config.URL_BASE, rooms=rooms, pubkey=crypto.server_pubkey_hex
    )


@views.get("/r/<Room:room>/")
def view_room(room):
    """
    Publicly accessible URL that displays a room (including recent messages) to a web browser.  This
    isn't a normal SOGS client endpoint, but rather a convenience web page for people who follow a
    SOGS pseudo-URL, that displays the SOGS URL and QR code along with a list of recent messages.
    """
    if not room.default_read:
        abort(http.FORBIDDEN)

    return render_template("view_room.html", room=room, show_recent=config.HTTP_SHOW_RECENT)


@views.get("/r/<Room:room>/invite.png")
def serve_invite_qr(room):
    """
    URL that generates a SOGS open group URL in QR code format for consumption by a mobile device.
    This isn't a normal SOGS client endpoint, but rather part of the a convenience web page for
    people who view the SOGS URL in a browser and want to scan the URL into another device (i.e.
    mobile Session).
    """
    if not room.default_read:
        abort(http.FORBIDDEN)

    img = qrcode.make(room.url)
    data = BytesIO()
    img = img.resize((512, 512), NEAREST)
    img.save(data, "PNG")
    return Response(data.getvalue(), mimetype="image/png")
