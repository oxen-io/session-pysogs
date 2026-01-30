from sogs import db, utils
from request import sogs_get, sogs_post
from util import pad64
import time


def test_global_mods(client, room, room2, user, user2, mod, admin, global_admin, global_mod):
    assert not room2.check_moderator(user)
    assert not room2.check_moderator(user2)

    # Track expected info_updates values; the initial values are because creating the mod/admin/etc.
    # fixtures imported here perform db modifications that trigger updates (2 global mods + 2 mods
    # of `room`):
    iu = {'test-room': 4, 'room2': 2}

    url_u1_mod = f'/user/{user.session_id}/moderator'
    url_u2_mod = f'/user/{user2.session_id}/moderator'

    # No one except global_admin should be able to add a global moderator:
    for u in (user, user2, mod, admin, global_mod):
        r = sogs_post(client, url_u2_mod, {'global': True, 'moderator': True}, u)
        assert r.status_code == 403

    r = sogs_post(client, url_u2_mod, {'global': True, 'moderator': True}, global_admin)
    assert r.status_code == 200
    for k in iu.keys():
        iu[k] += 1
    assert r.json == {'info_updates': iu}

    user2._refresh()
    assert user2.global_moderator
    assert not user2.global_admin
    room2._refresh(perms=True)
    assert room2.check_moderator(user2)
    assert not room2.check_admin(user2)

    r = sogs_post(client, url_u2_mod, {'global': True, 'moderator': True}, user2)
    assert r.status_code == 403

    r = sogs_post(client, url_u2_mod, {'global': True, 'moderator': False}, global_admin)
    assert r.status_code == 200
    for k in iu.keys():
        iu[k] += 1
    assert r.json == {'info_updates': iu}
    user2._refresh()
    room2._refresh(perms=True)
    assert not user2.global_moderator
    assert not user2.global_admin
    assert not room2.check_moderator(user2)

    r = sogs_post(client, url_u2_mod, {'global': True, 'admin': True}, global_admin)
    assert r.status_code == 200
    for k in iu.keys():
        iu[k] += 1
    assert r.json == {'info_updates': iu}
    user2._refresh()
    room2._refresh(perms=True)
    assert user2.global_moderator
    assert user2.global_admin
    assert room2.check_moderator(user2)
    assert room2.check_admin(user2)

    r = sogs_post(client, url_u1_mod, {'global': True, 'admin': True}, user2)
    assert r.status_code == 200
    for k in iu.keys():
        iu[k] += 1
    assert r.json == {'info_updates': iu}
    user._refresh()
    assert user.global_admin and user.global_moderator

    # Removing moderator also implicitly removes admin:
    r = sogs_post(client, url_u1_mod, {'global': True, 'moderator': False}, user2)
    assert r.status_code == 200
    for k in iu.keys():
        iu[k] += 1
    assert r.json == {'info_updates': iu}
    user._refresh()
    assert not user.global_admin and not user.global_moderator

    sogs_post(client, url_u2_mod, {'global': True, 'moderator': False}, global_admin)

    # Test other admin/moderator parameter interactions
    r = sogs_post(
        client, url_u2_mod, {'global': True, 'admin': True, 'moderator': True}, global_admin
    )
    assert r.status_code == 200
    user2._refresh()
    for k in iu.keys():
        iu[k] += 2
    assert r.json == {'info_updates': iu}
    assert user2.global_admin and user2.global_moderator

    r = sogs_post(
        client, url_u2_mod, {'global': True, 'admin': False, 'moderator': False}, global_admin
    )
    assert r.status_code == 200
    for k in iu.keys():
        iu[k] += 1
    assert r.json == {'info_updates': iu}
    user2._refresh()
    assert not user2.global_admin and not user2.global_moderator

    # admin=false, moderator=true should remove admin (if present) and add moderator (if not)
    # First make u2 an admin:
    sogs_post(client, url_u2_mod, {'global': True, 'admin': True}, global_admin)
    sogs_post(client, url_u2_mod, {'global': True, 'admin': False, 'moderator': True}, global_admin)
    sogs_post(client, url_u1_mod, {'global': True, 'admin': False, 'moderator': True}, global_admin)

    user._refresh()
    user2._refresh()
    assert user.global_moderator
    assert not user.global_admin
    assert user2.global_moderator
    assert not user2.global_admin

    # admin=false, moderator omitted: removes admin (if present), maintaining moderator if present,
    # but doesn't make non-mods/admins into mods.
    sogs_post(client, url_u1_mod, {'global': True, 'moderator': False}, global_admin)
    sogs_post(client, url_u2_mod, {'global': True, 'admin': True}, global_admin)

    # Preconditions:
    user._refresh()
    user2._refresh()
    assert not user.global_moderator
    assert not user.global_admin
    assert user2.global_moderator
    assert user2.global_admin

    sogs_post(client, url_u1_mod, {'global': True, 'admin': False}, global_admin)
    sogs_post(client, url_u2_mod, {'global': True, 'admin': False}, global_admin)

    user._refresh()
    user2._refresh()
    assert not user.global_moderator
    assert not user.global_admin
    assert user2.global_moderator
    assert not user2.global_admin

    # admin omitted, moderator=True: adds moderator permission if not present, doesn't affect admin
    sogs_post(client, url_u1_mod, {'global': True, 'moderator': False}, global_admin)
    sogs_post(client, url_u2_mod, {'global': True, 'admin': True}, global_admin)

    # Preconditions:
    user._refresh()
    user2._refresh()
    assert not user.global_moderator
    assert not user.global_admin
    assert user2.global_moderator
    assert user2.global_admin

    sogs_post(client, url_u1_mod, {'global': True, 'moderator': True}, global_admin)
    sogs_post(client, url_u2_mod, {'global': True, 'moderator': True}, global_admin)

    user._refresh()
    user2._refresh()
    assert user.global_moderator
    assert not user.global_admin
    assert user2.global_moderator
    assert user2.global_admin

    # moderator=false, admin=true: Impossible and is an error
    r = sogs_post(
        client, url_u2_mod, {'global': True, 'moderator': False, 'admin': True}, global_admin
    )
    assert r.status_code == 400


def test_room_mods(client, room, room2, user, user2, mod, admin, global_admin, global_mod):
    # Track expected info_updates values; the initial values are because creating the mod/admin/etc.
    # fixtures imported here perform db modifications that trigger updates (2 global mods + 2 mods
    # of `room`):
    iu = 4
    iu2 = 2

    assert not room.check_moderator(user)
    assert not room.check_moderator(user2)
    assert not room2.check_moderator(user)
    assert not room2.check_moderator(user2)

    def refresh():
        user._refresh()
        user2._refresh()
        room._refresh(perms=True)
        room2._refresh(perms=True)

    url_u2_mod = f'/user/{user2.session_id}/moderator'
    url_u1_mod = f'/user/{user.session_id}/moderator'

    # No one except admins should be able to add a room moderator:
    for u in (user, user2, mod, global_mod):
        r = sogs_post(client, url_u2_mod, {'rooms': ['*'], 'moderator': True}, u)
        assert r.status_code == 403

    r = sogs_post(client, url_u2_mod, {'rooms': ['test-room'], 'moderator': True}, global_admin)
    assert r.status_code == 200
    iu += 1
    assert r.json == {'info_updates': {'test-room': iu}}
    r = sogs_post(client, url_u1_mod, {'rooms': ['*'], 'moderator': True}, admin)
    assert r.status_code == 200
    iu += 1  # room2 doesn't change (even with '*') because `admin` isn't an admin of it
    assert r.json == {'info_updates': {'test-room': iu}}

    refresh()
    assert not user.global_moderator
    assert not user.global_admin
    assert not user2.global_moderator
    assert not user2.global_admin
    assert room.check_moderator(user2)
    assert room.check_moderator(user)
    assert not room.check_admin(user2)
    assert not room.check_admin(user)
    assert not room2.check_moderator(user)
    assert not room2.check_moderator(user2)

    r = sogs_post(client, url_u2_mod, {'rooms': ['*'], 'moderator': True}, user2)
    assert r.status_code == 403

    r = sogs_post(client, url_u1_mod, {'rooms': ['*'], 'moderator': False}, global_admin)
    assert r.status_code == 200
    iu += 1  # user isn't a moderator of room2, so room2's value doesn't change
    assert r.json == {'info_updates': {'test-room': iu, 'room2': iu2}}

    r = sogs_post(client, url_u2_mod, {'rooms': ['*'], 'moderator': False}, global_admin)
    assert r.status_code == 200
    iu += 1  # user2 isn't a moderator of room2, so room2's value doesn't change
    assert r.json == {'info_updates': {'test-room': iu, 'room2': iu2}}
    refresh()
    assert not user.global_moderator
    assert not user2.global_moderator
    assert not room.check_moderator(user)
    assert not room.check_moderator(user2)
    assert not room2.check_moderator(user)
    assert not room2.check_moderator(user2)

    # Make user2 a moderator of both rooms
    r = sogs_post(client, url_u2_mod, {'rooms': ['*'], 'moderator': True}, global_admin)
    assert r.status_code == 200
    iu += 1
    iu2 += 1
    assert r.json == {'info_updates': {'test-room': iu, 'room2': iu2}}
    refresh()
    assert not user.global_moderator
    assert not user2.global_moderator
    assert not room.check_moderator(user)
    assert room.check_moderator(user2)
    assert not room2.check_moderator(user)
    assert room2.check_moderator(user2)
    assert not room.check_admin(user)
    assert not room.check_admin(user2)
    assert not room2.check_admin(user)
    assert not room2.check_admin(user2)

    # Make user a admin of room2
    r = sogs_post(client, url_u1_mod, {'rooms': ['room2'], 'admin': True}, global_admin)
    assert r.status_code == 200
    iu2 += 1
    assert r.json == {'info_updates': {'room2': iu2}}
    refresh()
    assert not user.global_moderator
    assert not user2.global_moderator
    assert not room.check_moderator(user)
    assert room.check_moderator(user2)
    assert room2.check_moderator(user)
    assert room2.check_moderator(user2)
    assert not room.check_admin(user)
    assert not room.check_admin(user2)
    assert room2.check_admin(user)
    assert not room2.check_admin(user2)

    # user can promote user2 to admin but only in room2
    r = sogs_post(client, url_u2_mod, {'rooms': ['*'], 'admin': True}, user)
    assert r.status_code == 200
    iu2 += 1
    assert r.json == {'info_updates': {'room2': iu2}}
    refresh()
    assert not user.global_moderator
    assert not user2.global_moderator
    assert not room.check_moderator(user)
    assert room.check_moderator(user2)
    assert room2.check_moderator(user)
    assert room2.check_moderator(user2)
    assert not room.check_admin(user)
    assert not room.check_admin(user2)
    assert room2.check_admin(user)
    assert room2.check_admin(user2)

    # Make sure that we check *all* the given rooms for admin status:
    r = sogs_post(client, url_u2_mod, {'rooms': ['room2', 'test-room'], 'moderator': True}, user)
    assert r.status_code == 403
    r = sogs_post(client, url_u2_mod, {'rooms': ['test-room', 'room2'], 'moderator': True}, user)
    assert r.status_code == 403

    # Removing moderator also implicitly removes admin:
    r = sogs_post(client, url_u1_mod, {'rooms': ['room2'], 'moderator': False}, user2)
    assert r.status_code == 200
    iu2 += 1
    assert r.json == {'info_updates': {'room2': iu2}}
    refresh()
    assert not user.global_moderator
    assert not user2.global_moderator
    assert not room.check_moderator(user)
    assert room.check_moderator(user2)
    assert not room2.check_moderator(user)
    assert room2.check_moderator(user2)
    assert not room.check_admin(user)
    assert not room.check_admin(user2)
    assert not room2.check_admin(user)
    assert room2.check_admin(user2)

    def clear():
        sogs_post(client, url_u1_mod, {'rooms': ['*'], 'moderator': False}, global_admin)
        sogs_post(client, url_u2_mod, {'rooms': ['*'], 'moderator': False}, global_admin)
        refresh()
        assert not any(r.check_moderator(u) for u in (user, user2) for r in (room, room2))

    # Multi-room addition:
    clear()
    iu += 1
    iu2 += 1
    r = sogs_post(client, url_u1_mod, {'rooms': ['*'], 'admin': True}, global_admin)
    assert r.status_code == 200
    iu += 1
    iu2 += 1
    assert r.json == {'info_updates': {'test-room': iu, 'room2': iu2}}
    r = sogs_post(client, url_u2_mod, {'rooms': ['*'], 'moderator': True}, user)
    assert r.status_code == 200
    iu += 1
    iu2 += 1
    assert r.json == {'info_updates': {'test-room': iu, 'room2': iu2}}
    refresh()
    assert not user.global_moderator
    assert not user2.global_moderator
    assert room.check_moderator(user)
    assert room.check_moderator(user2)
    assert room2.check_moderator(user)
    assert room2.check_moderator(user2)
    assert room.check_admin(user)
    assert not room.check_admin(user2)
    assert room2.check_admin(user)
    assert not room2.check_admin(user2)

    # Test other admin/moderator parameter interactions
    r = sogs_post(
        client, url_u2_mod, {'rooms': ['test-room'], 'admin': True, 'moderator': True}, admin
    )
    assert r.status_code == 200
    iu += 1
    assert r.json == {'info_updates': {'test-room': iu}}
    refresh()
    assert room.check_moderator(user2)
    assert room.check_admin(user2)

    r = sogs_post(
        client, url_u2_mod, {'rooms': ['test-room'], 'admin': False, 'moderator': False}, admin
    )
    assert r.status_code == 200
    iu += 1
    assert r.json == {'info_updates': {'test-room': iu}}
    refresh()
    assert not room.check_moderator(user2)

    # admin=false, moderator=true should remove admin (if present) and add moderator (if not)
    # First make u2 an admin:
    clear()
    sogs_post(client, url_u2_mod, {'rooms': ['test-room'], 'admin': True}, admin)
    sogs_post(
        client, url_u2_mod, {'rooms': ['test-room'], 'admin': False, 'moderator': True}, admin
    )
    sogs_post(
        client, url_u1_mod, {'rooms': ['test-room'], 'admin': False, 'moderator': True}, admin
    )

    refresh()
    assert not room.check_admin(user)
    assert not room.check_admin(user2)
    assert room.check_moderator(user)
    assert room.check_moderator(user2)

    # admin=false, moderator omitted: removes admin (if present), maintaining moderator if present,
    # but doesn't make non-mods/admins into mods.
    sogs_post(client, url_u1_mod, {'rooms': ['test-room'], 'moderator': False}, admin)
    sogs_post(client, url_u2_mod, {'rooms': ['test-room'], 'admin': True}, admin)

    # Preconditions:
    refresh()
    assert not room.check_moderator(user)
    assert room.check_admin(user2)

    sogs_post(client, url_u1_mod, {'rooms': ['test-room'], 'admin': False}, admin)
    sogs_post(client, url_u2_mod, {'rooms': ['test-room'], 'admin': False}, admin)

    refresh()
    assert not room.check_moderator(user)
    assert room.check_moderator(user2)
    assert not room.check_admin(user2)

    # admin omitted, moderator=True: adds moderator permission if not present, doesn't affect admin
    sogs_post(client, url_u1_mod, {'rooms': ['test-room'], 'moderator': False}, admin)
    sogs_post(client, url_u2_mod, {'rooms': ['test-room'], 'admin': True}, admin)

    # Preconditions:
    refresh()
    assert not room.check_moderator(user)
    assert room.check_admin(user2)

    sogs_post(client, url_u1_mod, {'rooms': ['test-room'], 'moderator': True}, admin)
    sogs_post(client, url_u2_mod, {'rooms': ['test-room'], 'moderator': True}, admin)

    refresh()
    assert room.check_moderator(user)
    assert not room.check_admin(user)
    assert room.check_moderator(user2)
    assert room.check_admin(user2)

    # moderator=false, admin=true: Impossible and is an error
    r = sogs_post(
        client, url_u2_mod, {'rooms': ['test-room'], 'moderator': False, 'admin': True}, admin
    )
    assert r.status_code == 400


def test_mod_visibility(client, room, user, user2, mod, admin, global_admin):
    iu = 3  # mod + admin + global admin
    s_mod, s_admin, s_gadmin, s_user = (
        mod.session_id,
        admin.session_id,
        global_admin.session_id,
        user.session_id,
    )

    def room_mods(u=user2):
        r = sogs_get(client, '/room/test-room', u)
        assert r.status_code == 200
        return tuple(
            r.json.get(x, [])
            for x in ('moderators', 'admins', 'hidden_moderators', 'hidden_admins')
        )

    url_u1_mod = f'/user/{user.session_id}/moderator'
    r = sogs_post(client, url_u1_mod, {'global': True, 'moderator': True}, global_admin)
    assert r.status_code == 200
    # Visibility = false, but should still update info_updates so that other mods/admins notice the
    # change:
    iu += 1
    assert r.json == {'info_updates': {'test-room': iu}}
    user._refresh()
    assert user.global_moderator
    assert not user.global_admin
    assert not user.visible_mod
    assert room_mods() == ([s_mod], [s_admin], [], [])
    assert room_mods(mod) == ([s_mod], [s_admin], [s_user], [s_gadmin])

    r = sogs_post(
        client, url_u1_mod, {'global': True, 'moderator': True, 'visible': True}, global_admin
    )
    assert r.status_code == 200
    # Flipping visibility (and nothing else) should still update info_updates:
    iu += 1
    assert r.json == {'info_updates': {'test-room': iu}}
    user._refresh()
    assert user.global_moderator
    assert not user.global_admin
    assert user.visible_mod
    assert room_mods() == (sorted([s_mod, s_user]), [s_admin], [], [])
    assert room_mods(mod) == (sorted([s_mod, s_user]), [s_admin], [], [s_gadmin])

    r = sogs_post(
        client, url_u1_mod, {'global': True, 'moderator': True, 'visible': False}, global_admin
    )
    assert r.status_code == 200
    user._refresh()
    assert user.global_moderator
    assert not user.global_admin
    assert not user.visible_mod
    assert room_mods() == ([s_mod], [s_admin], [], [])
    assert room_mods(mod) == ([s_mod], [s_admin], [s_user], [s_gadmin])

    sogs_post(client, url_u1_mod, {'global': True, 'moderator': False}, global_admin)
    sogs_post(client, url_u1_mod, {'global': True, 'admin': True, 'visible': True}, global_admin)
    room._refresh(perms=True)
    user._refresh()
    assert room.check_moderator(user)
    assert room.check_admin(user)
    assert user.visible_mod
    assert room_mods() == ([s_mod], sorted([s_admin, s_user]), [], [])
    assert room_mods(mod) == ([s_mod], sorted([s_admin, s_user]), [], [s_gadmin])

    sogs_post(client, url_u1_mod, {'global': True, 'admin': True}, global_admin)
    user._refresh()
    assert user.global_moderator
    assert user.global_admin
    assert not user.visible_mod
    assert room_mods() == ([s_mod], [s_admin], [], [])
    assert room_mods(mod) == ([s_mod], [s_admin], [], sorted([s_gadmin, s_user]))

    sogs_post(client, url_u1_mod, {'global': True, 'moderator': False}, global_admin)

    r = sogs_post(client, url_u1_mod, {'rooms': ['test-room'], 'moderator': True}, global_admin)
    assert r.status_code == 200
    assert room_mods() == (sorted([s_mod, s_user]), [s_admin], [], [])
    assert room_mods(mod) == (sorted([s_mod, s_user]), [s_admin], [], [s_gadmin])

    r = sogs_post(
        client,
        url_u1_mod,
        {'rooms': ['test-room'], 'moderator': True, 'visible': True},
        global_admin,
    )
    assert r.status_code == 200
    assert room_mods() == (sorted([s_mod, s_user]), [s_admin], [], [])
    assert room_mods(mod) == (sorted([s_mod, s_user]), [s_admin], [], [s_gadmin])

    r = sogs_post(
        client,
        url_u1_mod,
        {'rooms': ['test-room'], 'moderator': True, 'visible': False},
        global_admin,
    )
    assert r.status_code == 200
    assert room_mods() == ([s_mod], [s_admin], [], [])
    assert room_mods(mod) == ([s_mod], [s_admin], [s_user], [s_gadmin])

    sogs_post(client, url_u1_mod, {'rooms': ['test-room'], 'moderator': False}, global_admin)
    sogs_post(
        client, url_u1_mod, {'rooms': ['test-room'], 'admin': True, 'visible': True}, global_admin
    )
    assert room_mods() == ([s_mod], sorted([s_admin, s_user]), [], [])
    assert room_mods(mod) == ([s_mod], sorted([s_admin, s_user]), [], [s_gadmin])

    sogs_post(
        client, url_u1_mod, {'rooms': ['test-room'], 'admin': True, 'visible': False}, global_admin
    )
    assert room_mods() == ([s_mod], [s_admin], [], [])
    assert room_mods(mod) == ([s_mod], [s_admin], [], sorted([s_user, s_gadmin]))

    sogs_post(client, url_u1_mod, {'rooms': ['test-room'], 'admin': True}, global_admin)
    assert room_mods() == ([s_mod], sorted([s_admin, s_user]), [], [])
    assert room_mods(mod) == ([s_mod], sorted([s_admin, s_user]), [], [s_gadmin])


def test_bans(client, room, room2, user, user2, mod, global_mod):
    url_ban = f'/user/{user.session_id}/ban'
    url_unban = f'/user/{user.session_id}/unban'
    post = {"data": utils.encode_base64(b"post"), "signature": utils.encode_base64(pad64("sig"))}

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201

    r = sogs_post(client, url_ban, {'rooms': ['test-room']}, mod)
    assert r.status_code == 200

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    r = sogs_post(client, "/room/test-room/message", post, user2)
    assert r.status_code == 201
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 201

    r = sogs_post(client, url_unban, {'rooms': ['test-room']}, mod)
    assert r.status_code == 200

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201

    r = sogs_post(client, url_ban, {'rooms': ['*']}, global_mod)
    assert r.status_code == 200

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 403

    r = sogs_post(client, "/room/test-room/message", post, user2)
    assert r.status_code == 201

    r = sogs_post(client, url_unban, {'rooms': ['*']}, mod)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 403

    r = sogs_post(client, url_unban, {'rooms': ['*']}, global_mod)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 201

    r = sogs_post(client, url_ban, {'global': True}, mod)
    assert r.status_code == 403
    r = sogs_post(client, url_ban, {'global': True}, global_mod)
    assert r.status_code == 200

    # With a global ban we shouldn't be able to access
    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 403
    r = sogs_get(client, "/rooms", user)
    assert r.status_code == 403

    r = sogs_post(client, "/room/test-room/message", post, user2)
    assert r.status_code == 201

    r = sogs_post(client, url_unban, {'global': True}, mod)
    assert r.status_code == 403
    r = sogs_post(client, url_unban, {'global': True}, global_mod)
    assert r.status_code == 200
    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 201

    # Test bad arguments properly err:
    assert [
        sogs_post(client, url_ban, data, global_mod).status_code
        for data in (
            {'global': True, 'rooms': ['abc']},
            {},
            {'rooms': []},
            {'global': False, 'rooms': []},
            {'global': False, 'rooms': None},
            {'rooms': ['test-room', '*']},
            {'rooms': ['*', 'test-room']},
        )
    ] == [400] * 7


def test_ban_timeouts(client, room, room2, user, mod, global_mod):
    url_ban = f'/user/{user.session_id}/ban'
    url_unban = f'/user/{user.session_id}/unban'
    post = {"data": utils.encode_base64(b"post"), "signature": utils.encode_base64(pad64("sig"))}

    r = sogs_post(client, url_ban, {'rooms': ['*'], 'timeout': 0.001}, global_mod)
    assert r.status_code == 200

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 403

    from sogs.cleanup import cleanup

    time.sleep(0.002)
    assert cleanup() == (0, 0, 0, 2, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 201

    r = sogs_post(client, url_ban, {'rooms': ['*'], 'timeout': 30}, mod)
    assert r.status_code == 200

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 201

    # The timed ban shouldn't expire yet:
    assert cleanup() == (0, 0, 0, 0, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 201

    # Handle overlapping timeouts.

    # If we add a ban with a timeout then ban with a different timeout, the second one should
    # replace the first one.

    # Replace the currently active 30s ban with one that expires sooner
    r = sogs_post(client, url_ban, {'rooms': ['*'], 'timeout': 0.001}, mod)
    assert r.status_code == 200

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    time.sleep(0.002)
    assert cleanup() == (0, 0, 0, 1, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201

    # Make sure we can replace a short one with a longer one
    r = sogs_post(client, url_ban, {'rooms': ['*'], 'timeout': 0.001}, mod)
    assert r.status_code == 200
    r = sogs_post(client, url_ban, {'rooms': ['*'], 'timeout': 30}, mod)
    assert r.status_code == 200

    time.sleep(0.002)
    assert cleanup() == (0, 0, 0, 0, 0)

    sogs_post(client, url_ban, {'rooms': ['*'], 'timeout': 0.001}, mod)
    time.sleep(0.002)
    assert cleanup() == (0, 0, 0, 1, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201

    # If we add a ban with a timeout *then* we ban again without a timeout, we want to be sure the
    # timeout gets cancelled.

    assert sogs_post(client, url_ban, {'rooms': ['*'], 'timeout': 0.001}, mod).status_code == 200
    assert sogs_post(client, url_ban, {'rooms': ['*']}, mod).status_code == 200
    time.sleep(0.005)

    assert cleanup() == (0, 0, 0, 0, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    # Unbanning should remove the ban future
    assert sogs_post(client, url_unban, {'rooms': ['*']}, mod).status_code == 200

    assert db.query('SELECT COUNT(*) FROM user_ban_futures').first()[0] == 0

    # Global bans can time out too:
    r = sogs_post(client, url_ban, {'global': True, 'timeout': 0.001}, global_mod)
    assert r.status_code == 200

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 403
    r = sogs_get(client, "/rooms", user)
    assert r.status_code == 403

    time.sleep(0.002)
    assert cleanup() == (0, 0, 0, 1, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201
    r = sogs_post(client, "/room/room2/message", post, user)
    assert r.status_code == 201

    # Re-banning with longer timeout:
    r = sogs_post(client, url_ban, {'global': True, 'timeout': 0.001}, global_mod)
    assert r.status_code == 200
    r = sogs_post(client, url_ban, {'global': True, 'timeout': 30}, global_mod)
    assert r.status_code == 200

    time.sleep(0.002)
    assert cleanup() == (0, 0, 0, 0, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    # global ban with a shorter timeout:
    r = sogs_post(client, url_ban, {'global': True, 'timeout': 0.001}, global_mod)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 403

    time.sleep(0.002)
    assert cleanup() == (0, 0, 0, 1, 0)

    r = sogs_post(client, "/room/test-room/message", post, user)
    assert r.status_code == 201
