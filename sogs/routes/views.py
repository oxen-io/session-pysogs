from flask import abort, render_template, Response, Blueprint

from ..utils import message_body, decode_base64, message_contents
from .. import config, crypto, http
from ..model.room import get_accessible_rooms
from ..model.user import User
from .messages import message_single, messages_recent
from . import auth, converters  # noqa: F401
from .. import session_pb2 as protobuf
import time


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
    messageId = 100
    response = ''
    print()
    try:
        # response = message_single(room=room, msg_id=messageId)
        response = messages_recent(room=room)
        print('   +++   NO ERROR   +++   ')
        if response.status_code == 200:
            print("     ===     EXISTS      ===   ")
                        
            request_data = response.json[0]['data']
            signature = response.json[0]['signature']
            request = response.json[0]
            epoch_time = request['posted']
            decoded_data = decode_base64(request_data)
            print('protobuf')
            print(request_data)
            # content = protobuf.Content()
            print(protobuf.Content().ParseFromString(decoded_data) )
            print()
            print('MSG BODY:')
            print(type(response.json[0]) )
            print(request )
            print(message_contents(decoded_data) )
            my_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_time))
            print(my_time)
            # print(msg )
            print()
        else:
            print("   !!!   NO MESSAGE  !!!   ")
        print()
    except Exception as e:
        print("ERROR MSG: {}".format(e))
    
    if not room.default_read:
        abort(http.FORBIDDEN)

    return render_template(
        "view_room.html",
        room=room,
        show_recent=config.HTTP_SHOW_RECENT,
        test='yeehaw'
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
