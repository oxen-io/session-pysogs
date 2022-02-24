from .. import config, db, http, utils
from ..model import room as mroom
from ..web import app
from . import auth

from flask import abort, jsonify, g, Blueprint, request

# Room-related routes


rooms = Blueprint('rooms', __name__)


def get_room_info(room):
    mods, admins, h_mods, h_admins = room.get_mods(g.user)

    rr = {
        'token': room.token,
        'name': room.name,
        'info_updates': room.info_updates,
        'message_sequence': room.message_sequence,
        'created': room.created,
        'active_users': room.active_users(),
        'active_users_cutoff': int(config.ROOM_DEFAULT_ACTIVE_THRESHOLD * 86400),
        'moderators': mods,
        'admins': admins,
        'read': room.check_read(g.user),
        'write': room.check_write(g.user),
        'upload': room.check_upload(g.user),
    }

    if room.description is not None:
        rr['description'] = room.description

    if room.image_id is not None:
        rr['image_id'] = room.image_id

    pinned = room.pinned_messages
    if pinned:
        rr['pinned_messages'] = pinned

    if h_mods:
        rr['hidden_moderators'] = h_mods
    if h_admins:
        rr['hidden_admins'] = h_admins

    if room.check_moderator(g.user):
        rr['moderator'] = True
        rr['default_read'] = room.default_read
        rr['default_accessible'] = room.default_accessible
        rr['default_write'] = room.default_write
        rr['default_upload'] = room.default_upload
    if room.check_admin(g.user):
        rr['admin'] = True
    if g.user:
        if g.user.global_moderator:
            rr['global_moderator'] = True
        if g.user.global_admin:
            rr['global_admin'] = True

    return rr


@rooms.get("/room/<Room:room>")
@auth.accessible_required
def get_one_room(room):
    return jsonify(get_room_info(room))


@rooms.get("/rooms")
def get_rooms():
    return jsonify([get_room_info(room=r) for r in mroom.get_accessible_rooms(g.user)])


BAD_NAME_CHARS = {c: None for c in range(32)}
BAD_DESCRIPTION_CHARS = {c: None for c in range(32) if not (0x09 <= c <= 0x0A)}


@rooms.put("/room/<Room:room>")
@auth.admin_required
def update_room(room):

    req = request.json

    with db.transaction():
        did = False
        if 'name' in req:
            n = req['name']
            if not isinstance(n, str):
                app.logger.warning(f"Room update with invalid name: {type(n)} != str")
                abort(http.BAD_REQUEST)
            room.name = n.translate(BAD_NAME_CHARS)
            did = True
        if 'description' in req:
            d = req['description']
            if not (d is None or isinstance(d, str)):
                app.logger.warning(f"Room update: invalid description: {type(d)} is not str, null")
                abort(http.BAD_REQUEST)
            if d is not None:
                d = d.translate(BAD_DESCRIPTION_CHARS)
                if len(d) == 0:
                    d = None

            room.description = d
            did = True
        read, accessible, write, upload = (
            req.get('default_' + x) for x in ('read', 'accessible', 'write', 'upload')
        )
        for val in (read, accessible, write, upload):
            if not (val is None or isinstance(val, bool) or isinstance(val, int)):
                app.logger.warning(
                    "Room update: default_read/accessible/write/upload must be bool, not "
                    f"{type(val)}"
                )
                abort(http.BAD_REQUEST)

        if read is not None:
            room.default_read = bool(read)
            did = True
        if accessible is not None:
            room.default_accessible = bool(accessible)
            did = True
        if write is not None:
            room.default_write = bool(write)
            did = True
        if upload is not None:
            room.default_upload = bool(upload)
            did = True

        if not did:
            app.logger.warning("Room update: must include at least one field to update")
            abort(http.BAD_REQUEST)

    return jsonify({})


@rooms.get("/room/<Room:room>/pollInfo/<int:info_updated>")
@auth.read_required
def poll_room_info(room, info_updated):
    if g.user:
        g.user.update_room_activity(room)

    result = {
        'token': room.token,
        'active_users': room.active_users(),
        'read': room.check_read(g.user),
        'write': room.check_write(g.user),
        'upload': room.check_upload(g.user),
    }

    if room.info_updates != info_updated:
        result['details'] = get_room_info(room)

    if room.check_moderator(g.user):
        result['moderator'] = True
        result['default_read'] = room.default_read
        result['default_write'] = room.default_write
        result['default_upload'] = room.default_upload
    if room.check_admin(g.user):
        result['admin'] = True
    if g.user:
        if g.user.global_moderator:
            result['global_moderator'] = True
        if g.user.global_admin:
            result['global_admin'] = True

    return jsonify(result)


@rooms.get("/room/<Room:room>/messages/since/<int:seqno>")
@auth.read_required
def messages_since(room, seqno):
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, sequence=seqno))


@rooms.get("/room/<Room:room>/messages/before/<int:msg_id>")
@auth.read_required
def messages_before(room, msg_id):
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, before=msg_id))


@rooms.get("/room/<Room:room>/messages/recent")
@auth.read_required
def messages_recent(room):
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, recent=True))


@rooms.get("/room/<Room:room>/message/<int:msg_id>")
@auth.read_required
def message_single(room, msg_id):
    if g.user:
        g.user.update_room_activity(room)

    msgs = room.get_messages_for(g.user, single=msg_id)
    if not msgs:
        abort(http.NOT_FOUND)

    return utils.jsonify_with_base64(msgs[0])


@rooms.post("/room/<Room:room>/message")
@auth.user_required
def post_message(room):
    req = request.json

    # TODO: files tracking

    msg = room.add_post(
        g.user,
        data=utils.decode_base64(req.get('data')),
        sig=utils.decode_base64(req.get('signature')),
        whisper_to=req.get('whisper_to'),
        whisper_mods=bool(req.get('whisper_mods')),
    )

    return utils.jsonify_with_base64(msg), http.CREATED


@rooms.put("/room/<Room:room>/message/<int:msg_id>")
@auth.user_required
def edit_message(room, msg_id):
    req = request.json

    # TODO: files tracking

    room.edit_post(
        g.user,
        msg_id,
        data=utils.decode_base64(req.get('data')),
        sig=utils.decode_base64(req.get('signature')),
    )

    return jsonify({})


@rooms.post("/room/<Room:room>/pin/<int:msg_id>")
def message_pin(room, msg_id):
    room.pin(msg_id, g.user)
    return jsonify({})


@rooms.post("/room/<Room:room>/unpin/<int:msg_id>")
def message_unpin(room, msg_id):
    room.unpin(msg_id, g.user)
    return jsonify({})


@rooms.post("/room/<Room:room>/unpin/all")
def message_unpin_all(room):
    room.unpin_all(g.user)
    return jsonify({})
