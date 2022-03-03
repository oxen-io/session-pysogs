from flask import abort, render_template, Response, Blueprint

from .. import config, crypto, http
from ..model.room import get_accessible_rooms
from . import auth, converters  # noqa: F401


from io import BytesIO

import qrencode

from PIL.Image import NEAREST


views = Blueprint('views', __name__)


@views.get("/")
def serve_index():
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
    if not room.default_read:
        abort(http.FORBIDDEN)

    return render_template(
        "view_room.html",
        room=room,
        show_recent=config.HTTP_SHOW_RECENT,
    )


@views.get("/r/<Room:room>/invite.png")
def serve_invite_qr(room):
    if not room.default_read:
        abort(http.FORBIDDEN)

    img = qrencode.encode(room.url)
    data = BytesIO()
    img = img[-1].resize((512, 512), NEAREST)
    img.save(data, "PNG")
    return Response(data.getvalue(), mimetype="image/png")
