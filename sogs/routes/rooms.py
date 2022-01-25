from .. import config, http, utils
from ..model import room as mroom
from . import auth

from flask import abort, jsonify, g, Blueprint, request

# General purpose routes for things like capability retrieval and batching


rooms = Blueprint('rooms', __name__)


@rooms.get("/room/<Room:room>")
def get_one_room(room):
    mods, admins, h_mods, h_admins = room.get_mods(g.user)

    rr = {
        'token': room.token,
        'name': room.name,
        'description': room.description,
        'info_updates': room.info_updates,
        'message_sequence': room.message_sequence,
        'created': room.created,
        'active_users': room.active_users(),
        'active_users_cutoff': int(config.ROOM_DEFAULT_ACTIVE_THRESHOLD * 86400),
        'moderators': mods,
        'admins': admins,
        'moderator': room.check_moderator(g.user),
        'admin': room.check_admin(g.user),
        'read': room.check_read(g.user),
        'write': room.check_write(g.user),
        'upload': room.check_upload(g.user),
    }

    if room.image_id is not None:
        rr['image_id'] = room.image_id

    pinned = room.pinned_messages
    if pinned:
        rr['pinned_messages'] = pinned

    if h_mods:
        rr['hidden_moderators'] = h_mods
    if h_admins:
        rr['hidden_admins'] = h_admins

    if g.user:
        if g.user.global_moderator:
            rr['global_moderator'] = True
        if g.user.global_admin:
            rr['global_admin'] = True

    return rr


@rooms.get("/rooms")
def get_rooms():
    return jsonify([get_one_room(r) for r in mroom.get_readable_rooms(g.user)])


@rooms.get("/room/<Room:room>/pollInfo/<int:info_updated>")
def poll_room_info(room, info_updated):
    if g.user:
        g.user.update_room_activity(room)

    result = {
        'token': room.token,
        'active_users': room.active_users(),
        'moderator': room.check_moderator(g.user),
        'admin': room.check_admin(g.user),
        'read': room.check_read(g.user),
        'write': room.check_write(g.user),
        'upload': room.check_upload(g.user),
    }

    if room.info_updates != info_updated:
        result['details'] = get_one_room(room)

    if g.user:
        if g.user.global_moderator:
            result['global_moderator'] = True
        if g.user.global_admin:
            result['global_admin'] = True

    return jsonify(result)


@rooms.get("/room/<Room:room>/messages/since/<int:seqno>")
def messages_since(room, seqno):
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, sequence=seqno))


@rooms.get("/room/<Room:room>/messages/before/<int:msg_id>")
def messages_before(room, msg_id):
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, before=msg_id))


@rooms.get("/room/<Room:room>/messages/recent")
def messages_recent(room):
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, recent=True))


@rooms.get("/room/<Room:room>/message/<int:msg_id>")
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
