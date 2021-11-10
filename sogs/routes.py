from flask import abort, request, jsonify, render_template, Response
from .web import app
from . import crypto
from . import model
from . import db
from . import utils
from . import config
from . import http

from werkzeug.routing import BaseConverter, ValidationError

from io import BytesIO

import qrencode

from PIL.Image import NEAREST


class RoomTokenConverter(BaseConverter):
    regex = r"[\w-]{1,64}"

    def to_python(self, value):
        try:
            return model.Room(token=value)
        except model.NoSuchRoom:
            raise ValidationError()

    def to_value(self, value):
        return value.token


class SessionIDConverter(BaseConverter):
    regex = r"05[0-9a-fA-F]{64}"

    def to_python(self, value):
        return value


app.url_map.converters['Room'] = RoomTokenConverter
app.url_map.converters['SessionID'] = SessionIDConverter


@app.get("/")
def serve_index():
    rooms = model.get_rooms()
    if len(rooms) == 0:
        return render_template('setup.html')
    return render_template(
        "index.html", url_base=config.URL_BASE, rooms=rooms, pubkey=crypto.server_pubkey_hex
    )


@app.get("/view/room/<Room:room>")
def view_room(room):
    return render_template("view_room.html", room=room.token, room_url=utils.server_url(room.token))


@app.get("/view/<Room:room>/invite.png")
def serve_invite_qr(room):
    img = qrencode.encode(utils.server_url(room.token))
    data = BytesIO()
    img = img[-1].resize((512, 512), NEAREST)
    img.save(data, "PNG")
    return Response(data.getvalue(), mimetype="image/png")


@app.post("/room/<Room:room>/message")
def post_to_room(room):
    user = utils.get_session_id(request)
    if not user:
        # todo: correct handling
        abort(http.FORBIDDEN)


@app.get("/room/<Room:room>/messages/recent")
def get_recent_room_messages(room):
    """get list of recent messages"""
    limit = utils.get_int_param('limit', 100, min=1, max=256)

    msgs = list()
    with db.conn as conn:
        rows = conn.execute(
            """
            SELECT
                messages.id, session_id, posted, edited, data, data_size, signature
            FROM messages JOIN users ON messages.user = users.id
            WHERE messages.room = (SELECT id FROM rooms WHERE token = ?1)
                AND data IS NOT NULL
            ORDER BY messages.id DESC LIMIT ?2
            """,
            (room.token, limit),
        )
        for id, session_id, posted, edited, data, data_size, signature in rows:
            m = {
                'id': id,
                'session_id': session_id,
                'timestamp': utils.convert_time(posted),
                'signature': utils.encode_base64(signature),
            }
            if edited is not None:
                m['edited'] = edited
            if len(data) < data_size:
                # Re-pad the message (we strip off padding when storing)
                data += b'\x00' * (data_size - len(data))
            m['data'] = utils.encode_base64(data)
            msgs.append(m)

    return jsonify(msgs)
