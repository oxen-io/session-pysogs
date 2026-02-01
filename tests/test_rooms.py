import pytest
import time
import sogs.model.exc as exc
from sogs.model.room import Room, get_rooms
from sogs.model.file import File
from sogs import config
from request import sogs_put
from util import pad64, from_now


def test_create(room, room2):
    r3 = Room.create('Test_Room-3', name='Test room 3', description='Test suite testing room3')

    rooms = get_rooms()

    assert len(rooms) == 3

    assert rooms[0].token == 'room2'
    assert rooms[0].id == room2.id
    assert rooms[0].name == 'Room 2'
    assert rooms[0].description == 'Test suite testing room2'

    assert rooms[1].token == 'test-room'
    assert rooms[1].id == room.id
    assert rooms[1].name == 'Test room'
    assert rooms[1].description == 'Test suite testing room'

    assert rooms[2].token == 'Test_Room-3'
    assert rooms[2].id == r3.id
    assert rooms[2].name == 'Test room 3'
    assert rooms[2].description == 'Test suite testing room3'

    with pytest.raises(exc.AlreadyExists):
        Room.create('room2', name='x', description=None)


def test_token_insensitive(room):
    r = Room.create('Test_Ro-om', name='TR2', description='Test suite testing room2')

    r_a = Room(token='Test_Ro-om')
    r_b = Room(token='test_ro-om')
    r_c = Room(token='test_RO-OM')
    r_d = Room(token='TEST_RO-OM')

    assert r.id > 0

    assert r_a.id == r.id and r_a.token == r.token
    assert r_b.id == r.id and r_b.token == r.token
    assert r_c.id == r.id and r_c.token == r.token
    assert r_d.id == r.id and r_d.token == r.token

    with pytest.raises(exc.NoSuchRoom):
        Room(token='Test-Ro-om')


def test_delete(room, room2):
    assert len(get_rooms()) == 2

    room2.delete()

    rooms = get_rooms()
    assert len(rooms) == 1
    assert rooms[0].token == 'test-room'


def test_delete_populated(room, room2, user, client):
    assert len(get_rooms()) == 2

    # Tests a bug where room deletion would fail if the room had reactions
    m = room.add_post(user, "data 1".encode(), pad64("sig 1"))
    r = sogs_put(client, f"/room/{room.token}/reaction/{m['id']}/🍆", {}, user)
    assert r.status_code == 200
    room.delete()

    rooms = get_rooms()
    assert len(rooms) == 1
    assert rooms[0].token == 'room2'


def test_info(room):
    inf = room.info
    assert inf['id'] == 1
    assert inf['token'] == 'test-room'
    assert inf['name'] == 'Test room'
    assert inf['description'] == 'Test suite testing room'
    assert abs(inf['created'] - time.time()) <= 1
    assert 'image_id' not in inf
    assert inf['message_sequence'] == 0
    assert inf['info_updates'] == 0


def test_updates(room):
    assert room.message_sequence == 0 and room.info_updates == 0 and room.name == 'Test room'

    room.name = 'Test Room'
    assert room.name == 'Test Room'
    assert room.message_sequence == 0
    assert room.info_updates == 1

    room.description = 'new desc'
    assert room.description == 'new desc'
    assert room.message_sequence == 0
    assert room.info_updates == 2

    room.token = 'new-token'
    assert room.token == 'new-token'
    # update counts not altered; see the attribute in model/room.py for why
    assert room.message_sequence == 0
    assert room.info_updates == 2

    r2 = Room(id=room.id)
    assert r2.message_sequence == 0
    assert r2.info_updates == 2
    assert r2.name == 'Test Room' and r2.description == 'new desc' and r2.token == 'new-token'


def test_permissions(room, user, user2, mod, admin, global_mod, global_admin):
    # Public permissions:
    assert not room.check_permission(admin=True)
    assert not room.check_permission(moderator=True)
    assert room.check_permission(read=True)
    assert room.check_read()
    assert room.check_permission(write=True)
    assert room.check_write()
    assert room.check_permission(upload=True)
    assert room.check_upload()
    assert not room.check_permission(moderator=True, read=True)
    assert not room.check_permission(admin=True, read=True)
    assert not room.check_permission(admin=True, moderator=True, read=True)
    assert not room.check_permission(admin=True, moderator=True, write=True)
    assert room.check_permission(read=True, write=True, upload=True)

    # Regular user permissions, should be identical to the above:
    assert not room.check_permission(user, admin=True)
    assert not room.check_admin(user)
    assert not room.check_permission(moderator=True)
    assert not room.check_moderator(user)
    assert room.check_permission(user, read=True)
    assert room.check_read(user)
    assert room.check_permission(user, write=True)
    assert room.check_write(user)
    assert room.check_permission(user, upload=True)
    assert room.check_upload(user)
    assert not room.check_permission(user, moderator=True, read=True)
    assert not room.check_permission(user, admin=True, read=True)
    assert not room.check_permission(user, admin=True, moderator=True, read=True)
    assert not room.check_permission(user, admin=True, moderator=True, write=True)
    assert room.check_permission(user, read=True, write=True, upload=True)

    # Room Admin
    assert room.check_permission(admin, admin=True)
    assert room.check_admin(admin)
    assert room.check_permission(admin, moderator=True)
    assert room.check_moderator(admin)
    assert room.check_permission(admin, read=True)
    assert room.check_read(admin)
    assert room.check_permission(admin, write=True)
    assert room.check_write(admin)
    assert room.check_permission(admin, upload=True)
    assert room.check_upload(admin)
    assert room.check_permission(admin, moderator=True, read=True)
    assert room.check_permission(admin, admin=True, read=True)
    assert room.check_permission(admin, admin=True, moderator=True, read=True)
    assert room.check_permission(admin, admin=True, moderator=True, write=True)
    assert room.check_permission(admin, read=True, write=True, upload=True)

    # Global admin
    assert room.check_permission(global_admin, admin=True)
    assert room.check_admin(global_admin)
    assert room.check_permission(global_admin, moderator=True)
    assert room.check_moderator(global_admin)
    assert room.check_permission(global_admin, read=True)
    assert room.check_read(global_admin)
    assert room.check_permission(global_admin, write=True)
    assert room.check_write(global_admin)
    assert room.check_permission(global_admin, upload=True)
    assert room.check_upload(global_admin)
    assert room.check_permission(global_admin, moderator=True, read=True)
    assert room.check_permission(global_admin, admin=True, read=True)
    assert room.check_permission(global_admin, admin=True, moderator=True, read=True)
    assert room.check_permission(global_admin, admin=True, moderator=True, write=True)
    assert room.check_permission(global_admin, read=True, write=True, upload=True)

    # Room moderator
    assert not room.check_permission(mod, admin=True)
    assert not room.check_admin(mod)
    assert room.check_permission(mod, moderator=True)
    assert room.check_moderator(mod)
    assert room.check_permission(mod, read=True)
    assert room.check_read(mod)
    assert room.check_permission(mod, write=True)
    assert room.check_write(mod)
    assert room.check_permission(mod, upload=True)
    assert room.check_upload(mod)
    assert room.check_permission(mod, moderator=True, read=True)
    assert not room.check_permission(mod, admin=True, read=True)
    assert not room.check_permission(mod, admin=True, moderator=True, read=True)
    assert not room.check_permission(mod, admin=True, moderator=True, write=True)
    assert room.check_permission(mod, read=True, write=True, upload=True)

    # Global moderator
    assert not room.check_permission(global_mod, admin=True)
    assert not room.check_admin(global_mod)
    assert room.check_permission(global_mod, moderator=True)
    assert room.check_moderator(global_mod)
    assert room.check_permission(global_mod, read=True)
    assert room.check_read(global_mod)
    assert room.check_permission(global_mod, write=True)
    assert room.check_write(global_mod)
    assert room.check_permission(global_mod, upload=True)
    assert room.check_upload(global_mod)
    assert room.check_permission(global_mod, moderator=True, read=True)
    assert not room.check_permission(global_mod, admin=True, read=True)
    assert not room.check_permission(global_mod, admin=True, moderator=True, read=True)
    assert not room.check_permission(global_mod, admin=True, moderator=True, write=True)
    assert room.check_permission(global_mod, read=True, write=True, upload=True)

    # Restrict room uploads:
    room.default_upload = False
    assert not room.check_upload()
    assert not room.check_permission(upload=True, write=True)
    assert not room.check_upload(user)
    assert not room.check_permission(user, upload=True, write=True)
    assert room.check_upload(admin)
    assert room.check_upload(mod)
    assert room.check_upload(global_admin)
    assert room.check_upload(global_mod)
    assert room.check_write()
    assert room.check_write(user)

    # Restrict room posting
    room.default_write = False
    assert not room.check_upload()
    assert not room.check_write()
    assert not room.check_write(user)
    assert not room.check_permission(user, read=True, write=True, upload=True)
    assert not room.check_permission(user, read=True, write=True)
    assert room.check_permission(user, read=True)
    assert room.check_write(admin)
    assert room.check_write(mod)
    assert room.check_write(global_admin)
    assert room.check_write(global_mod)
    assert room.check_permission(mod, read=True, write=True, upload=True)
    assert room.check_read()
    assert room.check_read(user)

    # Restrict room reading
    room.default_read = False
    assert not room.check_read()
    assert not room.check_read(user)
    assert not room.check_write(user)
    assert not room.check_upload(user)
    assert not room.check_permission(user, read=True, write=True, upload=True)
    assert not room.check_permission(user, read=True, write=True)
    assert not room.check_permission(user, read=True)
    assert room.check_read(admin)
    assert room.check_read(mod)
    assert room.check_read(global_admin)
    assert room.check_read(global_mod)
    assert room.check_permission(mod, read=True, write=True, upload=True)
    assert not room.check_read(user2)
    assert not room.check_write(user2)
    assert not room.check_upload(user2)

    # Grant user2 read/write/upload permission
    room.set_permissions(user2, mod=mod, read=True)
    assert room.check_read(user2)
    assert not room.check_write(user2)
    assert not room.check_upload(user2)

    room.set_permissions(user2, mod=mod, write=True, upload=True)
    assert room.check_read(user2)
    assert room.check_write(user2)
    assert room.check_upload(user2)

    room.set_permissions(user2, mod=mod, read=False)
    assert not room.check_read(user2)
    assert room.check_write(user2)
    assert room.check_upload(user2)

    room.set_permissions(user2, mod=mod, upload=None)
    assert not room.check_read(user2)
    assert room.check_write(user2)
    assert not room.check_upload(user2)

    room.set_permissions(user2, mod=mod, read=True, write=None, upload=None)
    assert room.check_read(user2)
    assert not room.check_write(user2)
    assert not room.check_upload(user2)

    room.set_permissions(user2, mod=mod, read=True, write=None, upload=False)
    assert room.check_read(user2)
    assert not room.check_write(user2)
    assert not room.check_upload(user2)

    # Unrestrict again
    room.default_read, room.default_write, room.default_upload = True, True, True
    assert room.default_read
    assert room.default_write
    assert room.default_upload
    assert room.check_permission(user, read=True, write=True, upload=True)
    assert room.check_permission(user, read=True, write=True)
    assert room.check_permission(user, read=True)

    # We have an explicit upload=False permission that should be preserved, but write should be
    # default so should not be granted:
    assert room.check_read(user2)
    assert room.check_write(user2)
    assert not room.check_upload(user2)

    # Clear all specific user2 permissions:
    room.set_permissions(user2, mod=mod, read=None, write=None, upload=None)
    assert room.check_read(user2)
    assert room.check_write(user2)
    assert room.check_upload(user2)

    # Revoke them all again:
    room.set_permissions(user2, mod=mod, read=False, write=False, upload=False)
    assert not room.check_read(user2)
    assert not room.check_write(user2)
    assert not room.check_upload(user2)
    assert room.check_read(user)
    assert room.check_write(user)
    assert room.check_upload(user)

    # Restrict posting, but not uploads (this should still disallow uploads unless the user also
    # gains the write permission some other way)
    room.default_write = False
    assert not room.default_write
    assert room.default_upload
    assert not room.check_upload()
    assert not room.check_upload(user)

    with pytest.raises(exc.BadPermission):
        room.set_permissions(user2, mod=user, read=None, write=None, upload=None)


def test_bans(room, user, user2, mod, admin, global_mod, global_admin):
    assert room.check_read(user)
    assert room.check_unbanned(user)
    assert room.check_permission(user, read=True, write=True, upload=True)
    assert room.check_read(user2)
    assert room.check_unbanned(user2)

    room.ban_user(user, mod=mod)
    assert not room.check_read(user)
    assert not room.check_unbanned(user)

    assert room.check_read(user2)
    assert room.check_unbanned(user2)

    assert room.unban_user(user, mod=mod)
    assert not room.unban_user(user, mod=mod)
    assert room.check_read(user)
    assert room.check_permission(user, read=True, write=True, upload=True)
    assert room.check_unbanned(user)

    room.ban_user(user, mod=mod, timeout=-1)
    assert not room.check_read(user)
    assert not room.check_unbanned(user)

    from sogs.cleanup import cleanup

    assert cleanup() == (0, 0, 0, 1, 0)

    room._refresh(perms=True)

    assert room.check_read(user)
    assert room.check_unbanned(user)
    assert room.check_permission(user, read=True, write=True, upload=True)

    assert not room.unban_user(user, mod=mod)

    with pytest.raises(exc.BadPermission):
        room.ban_user(user, mod=user2)

    room.ban_user(user, mod=admin)
    room.ban_user(user, mod=global_admin)
    room.ban_user(user, mod=global_mod)

    assert room.unban_user(user, mod=global_mod)


def test_mods(room, user, user2, mod, admin, global_mod, global_admin):
    room.set_moderator(user, added_by=admin)
    assert room.check_moderator(user)
    assert not room.check_admin(user)

    room.remove_moderator(user, removed_by=admin)
    assert not room.check_moderator(user)
    assert not room.check_admin(user)

    room.set_moderator(user, added_by=admin, admin=True)
    # Oh no, user is malicious!
    room.remove_moderator(admin, removed_by=user)
    room.remove_moderator(mod, removed_by=user)

    assert room.check_admin(user)
    assert not room.check_moderator(mod)
    assert not room.check_moderator(admin)
    assert not room.check_admin(admin)

    # These don't do anything because these are global, not room, admins/mods
    room.remove_moderator(global_admin, removed_by=user)
    room.remove_moderator(global_mod, removed_by=user)

    assert room.check_admin(global_admin)
    assert room.check_moderator(global_mod)

    with pytest.raises(exc.BadPermission):
        user.set_moderator(added_by=user, admin=True)
    with pytest.raises(exc.BadPermission):
        user.set_moderator(added_by=user, admin=False)

    # global mods don't have admin access:
    with pytest.raises(exc.BadPermission):
        room.remove_moderator(user, removed_by=global_mod)

    # global admin steps in to save the day, hurray!
    room.remove_moderator(user, removed_by=global_admin)
    room.set_moderator(admin, added_by=global_admin, admin=True)
    room.set_moderator(mod, added_by=global_admin, admin=True)

    assert not room.check_moderator(user)
    assert not room.check_admin(user)

    assert room.check_admin(admin)
    assert room.check_moderator(mod)
    assert room.check_admin(mod)

    # Oops, `mod` is only supposed to be a moderator, but she's honest and fixes it herself:
    room.set_moderator(mod, admin=False, added_by=mod)

    assert room.check_moderator(mod)
    assert not room.check_admin(mod)

    # Make user2 a hidden room admin
    room.set_moderator(user2, added_by=admin, admin=True, visible=False)
    assert room.check_moderator(user2)
    assert room.check_admin(user2)

    # Public mod list should only include mod and admin; the global ones are hidden as is user2
    vis_mods = [mod.session_id]
    vis_admins = [admin.session_id]
    hidden_mods = [global_mod.session_id]
    hidden_admins = sorted(x.session_id for x in (user2, global_admin))

    assert room.get_mods() == (vis_mods, vis_admins, [], [])
    assert room.get_mods(user) == (vis_mods, vis_admins, [], [])
    assert room.get_mods(mod) == (vis_mods, vis_admins, hidden_mods, hidden_admins)
    assert room.get_mods(user2) == (vis_mods, vis_admins, hidden_mods, hidden_admins)
    assert room.get_mods(global_admin) == (vis_mods, vis_admins, hidden_mods, hidden_admins)


def test_upload(room, user):
    import os

    file = File(id=room.upload_file(content=b'abc', uploader=user, filename="abc.txt", lifetime=30))

    assert file.id
    assert file.room.id and file.room.id == room.id
    assert file.uploader.id and file.uploader.id == user.id
    assert file.size == 3
    assert file.uploaded == from_now.now()
    assert file.expiry == from_now.seconds(30)
    assert os.path.isfile(file.path)
    assert os.path.getsize(file.path) == file.size
    assert file.path == f'{config.UPLOAD_PATH}/{room.token}/{file.id}_abc.txt'
    assert file.filename == 'abc.txt'

    # Legacy upload, with no filename:
    file = File(id=room.upload_file(content=b'defg', uploader=user))
    assert file.id
    assert file.room.id and file.room.id == room.id
    assert file.uploader.id and file.uploader.id == user.id
    assert file.size == 4
    assert file.uploaded == from_now.now()
    assert file.expiry == from_now.days(15)
    assert os.path.isfile(file.path)
    assert os.path.getsize(file.path) == file.size
    assert file.path == f'{config.UPLOAD_PATH}/{room.token}/{file.id}_(unnamed)'
    assert file.filename is None


def test_upload_expiry(room, user):
    import os

    file = File(id=room.upload_file(content=b'abc', uploader=user, filename="abc.txt", lifetime=-1))

    assert file.id
    assert file.uploaded == from_now.now()
    assert file.expiry == from_now.seconds(-1)
    assert os.path.isfile(file.path)
    assert os.path.getsize(file.path) == file.size
    assert file.path == f'{config.UPLOAD_PATH}/{room.token}/{file.id}_abc.txt'

    from sogs.cleanup import cleanup

    assert cleanup() == (1, 0, 0, 0, 0)

    with pytest.raises(exc.NoSuchFile):
        File(id=file.id)

    assert not os.path.exists(file.path)


def test_image(room, user):
    assert room.image is None

    fid = room.upload_file(content=b'abc', uploader=user, filename="abc.txt")

    room.image = fid
    assert room.image.id == fid
    assert room.image.size == 3
    assert room.image.filename == "abc.txt"
    assert room.image.expiry is None

    # Forcibly refetch the room to make sure we fetch the image properly from scratch
    room2 = Room(token=room.token)
    assert room2.image.id == fid
    assert room2.image.size == 3
    assert room2.image.filename == "abc.txt"
    assert room2.image.expiry is None


def test_image_expiries(room, user):
    """Replace the room image and make sure we have set an expiry on the old one"""

    fid1 = room.upload_file(content=b'abc', uploader=user, filename='abc.txt')
    f1 = File(id=fid1)
    f2 = File(id=room.upload_file(content=b'defg', uploader=user, filename='def.txt'))

    assert f1.expiry is not None

    room.image = f1

    assert room.image.id == fid1
    assert room.image.size == 3 and room.image.filename == 'abc.txt'
    assert room.image.expiry is None
    assert f1.expiry is None

    room.image = f2.id

    assert room.image.id == f2.id

    # We set it by id, so our f2 values are stale and need to be refetched:
    assert f2.expiry is not None

    f2 = File(id=f2.id)

    assert f2.expiry is None
    assert room.image.expiry is None
    assert room.image.id == f2.id
    assert f2.filename == 'def.txt'

    assert f1.expiry is not None


def test_pinning(room, room2, user, mod, admin, global_admin, no_rate_limit):
    msgs = [room.add_post(user, f"data {i}".encode(), pad64(f"sig {i}")) for i in range(1, 10)]

    with pytest.raises(exc.BadPermission):
        room.pin(msgs[3]['id'], user)
    with pytest.raises(exc.BadPermission):
        room.pin(msgs[4]['id'], mod)
    room.pin(msgs[5]['id'], admin)
    assert msgs[5]['id'] == 6

    assert room.pinned_messages[0].pop('pinned_at') == from_now.now()
    assert room.pinned_messages == [{"id": 6, "pinned_by": admin.session_id}]

    time.sleep(0.001)

    room.pin(7, global_admin)
    assert room.pinned_messages[0]['pinned_at'] == from_now.now()
    assert room.pinned_messages[0]['pinned_at'] < room.pinned_messages[1]['pinned_at']
    assert room.pinned_messages[1]['pinned_at'] == from_now.now()
    old_ts_t = room.pinned_messages[1]['pinned_at']
    rpm = room.pinned_messages.copy()
    for pm in rpm:
        del pm['pinned_at']
    assert rpm == [
        {"id": 6, "pinned_by": admin.session_id},
        {"id": 7, "pinned_by": global_admin.session_id},
    ]

    time.sleep(0.001)
    # Re-pin (will update its pinned timestamp and thus implicit reorder, along with pinned_by)
    room.pin(6, global_admin)

    assert room.pinned_messages[0]['pinned_at'] == from_now.now()
    assert room.pinned_messages[0]['pinned_at'] < room.pinned_messages[1]['pinned_at']
    assert room.pinned_messages[1]['pinned_at'] == from_now.now()
    assert old_ts_t == room.pinned_messages[0]['pinned_at']
    rpm = room.pinned_messages.copy()
    for pm in rpm:
        del pm['pinned_at']
    assert rpm == [
        {"id": 7, "pinned_by": global_admin.session_id},
        {"id": 6, "pinned_by": global_admin.session_id},
    ]

    # Non-existant id should fail
    with pytest.raises(exc.NoSuchPost):
        room.pin(123, admin)

    # Pinning some other room's message should fail
    with pytest.raises(exc.NoSuchPost):
        room2.pin(7, global_admin)

    assert not room2.pinned_messages


def test_active_users(room, user, user2):
    assert room.active_users == 0
    user.update_room_activity(room)
    room._refresh()
    assert room.active_users_last(1) == 1
    assert room.active_users == 0  # Doesn't update until the cleanup cycle

    from sogs.cleanup import cleanup

    cleanup()
    room._refresh()

    assert room.active_users == 1
    user2.update_room_activity(room)
    room._refresh()
    assert room.active_users == 1
    assert room.active_users_last(1) == 2

    cleanup()
    room._refresh()

    assert room.active_users == 2
    assert room.active_users_last(1) == 2
