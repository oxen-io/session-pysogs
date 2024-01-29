import time
from sogs.model.room import Room
from sogs.model.file import File
from sogs import utils, crypto
import sogs.config
from util import pad64, from_now, config_override
from auth import x_sogs
from request import sogs_get, sogs_post, sogs_put, sogs_post_raw, sogs_delete
import json


def test_list(client, room, room2, user, user2, admin, mod, global_mod, global_admin):
    room2.default_write = False
    room2.default_upload = False

    room3 = Room.create('room3', name='Room 3', description='Test suite testing room3')
    room3.default_read = False
    room3.default_write = False
    room3.default_upload = False

    room4 = Room.create('room4', name='Room 4', description='Secret room')
    room4.default_accessible = False
    room4.default_read = False
    room4.default_write = False
    room4.default_upload = False

    r2_expected = {
        "token": "room2",
        "name": "Room 2",
        "description": "Test suite testing room2",
        "info_updates": 2,
        "message_sequence": 0,
        "created": room2.created,
        "active_users": 0,
        "active_users_cutoff": int(sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [],
        "admins": [],
        "read": True,
        "write": False,
        "upload": False,
    }
    r2_exp_defs = {
        "default_read": True,
        "default_accessible": True,
        "default_write": False,
        "default_upload": False,
    }
    r_expected = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 4,
        "message_sequence": 0,
        "created": room.created,
        "active_users": 0,
        "active_users_cutoff": int(sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [mod.session_id],
        "admins": [admin.session_id],
        "read": True,
        "write": True,
        "upload": True,
    }
    r_exp_defs = {f"default_{x}": True for x in ('read', 'accessible', 'write', 'upload')}
    r3_expected = {
        "token": "room3",
        "name": "Room 3",
        "description": "Test suite testing room3",
        "info_updates": 0,
        "message_sequence": 0,
        "created": room3.created,
        "active_users": 0,
        "active_users_cutoff": int(sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [],
        "admins": [],
        "read": False,
        "write": False,
        "upload": False,
    }
    r3_exp_defs = {
        "default_read": False,
        "default_accessible": True,
        "default_write": False,
        "default_upload": False,
    }

    r4_expected = {
        "token": "room4",
        "name": "Room 4",
        "description": "Secret room",
        "info_updates": 0,
        "message_sequence": 0,
        "created": room4.created,
        "active_users": 0,
        "active_users_cutoff": int(sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [],
        "admins": [],
        "read": False,
        "write": False,
        "upload": False,
    }
    r4_exp_defs = {f"default_{x}": False for x in ('read', 'accessible', 'write', 'upload')}

    exp_mod = {
        **{p: True for p in ("moderator", "read", "write", "upload")},
        "hidden_moderators": [global_mod.session_id],
        "hidden_admins": [global_admin.session_id],
    }
    exp_admin = {**exp_mod, "admin": True}
    exp_gmod = {**exp_mod, "global_moderator": True}
    exp_gadmin = {**exp_admin, "global_moderator": True, "global_admin": True}

    room3.set_permissions(user2, mod=global_mod, read=True)
    room2.set_permissions(user2, mod=global_admin, write=True)
    room4.set_permissions(user2, mod=global_mod, accessible=True)

    # Unauthed user: should not see room4
    r = client.get("/rooms")
    assert r.status_code == 200
    assert r.json == [r2_expected, r3_expected, r_expected]

    r = sogs_get(client, "/rooms", user)
    assert r.status_code == 200
    assert r.json == [r2_expected, r3_expected, r_expected]

    r = sogs_get(client, "/rooms", user2)
    assert r.status_code == 200
    assert r.json == [
        {**r2_expected, "write": True},
        {**r3_expected, "read": True},
        r4_expected,
        r_expected,
    ]

    r = sogs_get(client, "/rooms", mod)
    assert r.status_code == 200
    assert r.json == [r2_expected, r3_expected, {**r_expected, **r_exp_defs, **exp_mod}]

    r = sogs_get(client, "/rooms", admin)
    assert r.status_code == 200
    assert r.json == [r2_expected, r3_expected, {**r_expected, **r_exp_defs, **exp_admin}]

    r = sogs_get(client, "/rooms", global_mod)
    assert r.status_code == 200
    assert r.json == [
        {**r2_expected, **r2_exp_defs, **exp_gmod},
        {**r3_expected, **r3_exp_defs, **exp_gmod},
        {**r4_expected, **r4_exp_defs, **exp_gmod},
        {**r_expected, **r_exp_defs, **exp_gmod},
    ]

    r = sogs_get(client, "/rooms", global_admin)
    assert r.status_code == 200
    assert r.json == [
        {**r2_expected, **r2_exp_defs, **exp_gadmin},
        {**r3_expected, **r3_exp_defs, **exp_gadmin},
        {**r4_expected, **r4_exp_defs, **exp_gadmin},
        {**r_expected, **r_exp_defs, **exp_gadmin},
    ]

    r = sogs_get(client, "/room/room3", user)
    assert r.status_code == 200
    assert r.json == r3_expected

    r = sogs_get(client, "/room/room3", user2)
    assert r.status_code == 200
    assert r.json == {**r3_expected, "read": True}

    r = sogs_get(client, "/room/room3", global_admin)
    assert r.status_code == 200
    assert r.json == {**r3_expected, **r3_exp_defs, **exp_gadmin}

    r = sogs_get(client, "/room/room4", user)
    assert r.status_code == 404
    assert not r.is_json

    r = sogs_get(client, "/room/room4", user2)
    assert r.status_code == 200
    assert r.json == r4_expected

    r = sogs_get(client, "/room/room4", global_admin)
    assert r.status_code == 200
    assert r.json == {**r4_expected, **r4_exp_defs, **exp_gadmin}


def test_visible_global_mods(client, room, user, mod, global_mod, global_admin):
    url_room = '/room/test-room'
    expect_room = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 3,
        "message_sequence": 0,
        "created": room.created,
        "active_users": 0,
        "active_users_cutoff": int(sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [mod.session_id],
        "admins": [],
        "read": True,
        "write": True,
        "upload": True,
    }
    r = sogs_get(client, url_room, user)
    assert r.status_code == 200
    assert r.json == expect_room

    expected_for_moderator = {
        **expect_room,
        **{'default_' + x: True for x in ('accessible', 'read', 'write', 'upload')},
        'global_moderator': True,
        'hidden_admins': [global_admin.session_id],
        'hidden_moderators': [global_mod.session_id],
        'moderator': True,
        'moderators': [mod.session_id],
    }
    r = sogs_get(client, "/room/test-room/pollInfo/0", global_mod)
    assert r.status_code == 200
    assert r.json == {
        'token': 'test-room',
        'active_users': 0,
        'details': expected_for_moderator,
        'read': True,
        'write': True,
        'upload': True,
        'moderator': True,
        'global_moderator': True,
        'default_accessible': True,
        'default_read': True,
        'default_write': True,
        'default_upload': True,
    }

    global_mod.set_moderator(added_by=global_admin, admin=False, visible=True)
    global_admin.set_moderator(added_by=global_admin, admin=True, visible=True)

    for e in (expect_room, expected_for_moderator):
        e["moderators"] = sorted([mod.session_id, global_mod.session_id])
        e["admins"] = [global_admin.session_id]
        e["info_updates"] += 2
    del expected_for_moderator["hidden_admins"]
    del expected_for_moderator["hidden_moderators"]

    r = sogs_get(client, url_room, user)
    assert r.status_code == 200
    assert r.json == expect_room

    r = sogs_get(client, url_room, mod)
    assert r.status_code == 200
    del expected_for_moderator["global_moderator"]
    assert r.json == expected_for_moderator


def test_updates(client, room, user, user2, mod, admin, global_mod, global_admin):
    url_room = '/room/test-room'
    r = sogs_get(client, url_room, user)
    assert r.status_code == 200
    expect_room = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 4,
        "message_sequence": 0,
        "created": room.created,
        "active_users": 0,
        "active_users_cutoff": int(sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [mod.session_id],
        "admins": [admin.session_id],
        "read": True,
        "write": True,
        "upload": True,
    }
    assert r.json == expect_room

    for u in (user, user2, mod, global_mod):
        r = sogs_put(client, url_room, {"name": "OMG ROOM!"}, u)
        assert r.status_code == 403

    assert sogs_get(client, url_room, user).json == expect_room

    r = sogs_put(client, url_room, {"name": "OMG ROOM!"}, admin)
    assert r.status_code == 200
    expect_room['name'] = "OMG ROOM!"
    expect_room['info_updates'] += 1

    assert sogs_get(client, url_room, user).json == expect_room

    r = sogs_put(
        client, url_room, {"name": "rrr", "description": "Tharr be pirrrates!"}, global_admin
    )
    assert r.status_code == 200
    expect_room['name'] = 'rrr'
    expect_room['description'] = 'Tharr be pirrrates!'
    expect_room['info_updates'] += 2

    assert sogs_get(client, url_room, user).json == expect_room

    r = sogs_put(client, url_room, {"default_write": False}, admin)
    assert r.status_code == 200
    expect_room['write'] = False
    expect_room['upload'] = False  # upload requires default_upload *and* write
    # expect_room['info_updates'] += 0  # permission updates don't increment info_updates

    assert sogs_get(client, url_room, user).json == expect_room

    expect_mod = {
        'read': True,
        'write': True,
        'upload': True,
        'default_read': True,
        'default_accessible': True,
        'default_write': False,
        'default_upload': True,
        'moderator': True,
        'moderators': [mod.session_id],
        'admins': [admin.session_id],
        'hidden_moderators': [global_mod.session_id],
        'hidden_admins': [global_admin.session_id],
    }
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}

    r = sogs_put(client, url_room, {"default_upload": False, "default_read": True}, admin)
    assert r.status_code == 200
    expect_mod['default_upload'] = False

    assert sogs_get(client, url_room, user).json == expect_room
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}

    r = sogs_put(client, url_room, {"default_read": False}, admin)
    assert r.status_code == 200
    expect_room['read'] = False
    expect_mod['default_read'] = False

    assert sogs_get(client, url_room, user).json == expect_room
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}

    r = sogs_put(
        client,
        url_room,
        {
            "default_read": True,
            "default_write": True,
            "default_upload": True,
            "name": "Gudaye, mytes!",
            "description": (
                "Room for learning to speak Australian\n\n"
                "Throw a shrimpie on the barbie and crack a coldie from the bottle-o!"
            ),
        },
        admin,
    )
    assert r.status_code == 200
    for x in ('read', 'write', 'upload'):
        expect_room[x] = True
    expect_room['name'] = "Gudaye, mytes!"
    expect_room['description'] = (
        "Room for learning to speak Australian\n\n"
        "Throw a shrimpie on the barbie and crack a coldie from the bottle-o!"
    )
    expect_room['info_updates'] += 2
    for x in ('read', 'write', 'upload'):
        expect_mod['default_' + x] = True

    assert sogs_get(client, url_room, user).json == expect_room
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}

    r = sogs_put(client, url_room, {"description": None}, admin)
    assert r.status_code == 200

    del expect_room['description']
    expect_room['info_updates'] += 1

    assert sogs_get(client, url_room, user).json == expect_room
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}

    r = sogs_put(client, url_room, {"description": "ddd"}, admin)
    expect_room['description'] = 'ddd'
    expect_room['info_updates'] += 1
    assert sogs_get(client, url_room, user).json == expect_room

    # empty string description should be treated as null
    r = sogs_put(client, url_room, {"description": ""}, admin)
    del expect_room['description']
    expect_room['info_updates'] += 1
    assert sogs_get(client, url_room, user).json == expect_room

    # Name strips out all control chars (i.e. anything below \x20); description strips out all
    # except newline (\x0a) and tab (\x09).
    r = sogs_put(
        client,
        url_room,
        {
            "description": f"a{''.join(chr(c) for c in range(33))}z",
            "name": f"a{''.join(chr(c) for c in range(33))}z",
        },
        admin,
    )
    expect_room['description'] = 'a\x09\x0a z'
    expect_room['name'] = 'a z'
    expect_room['info_updates'] += 2

    assert sogs_get(client, url_room, user).json == expect_room
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}

    # Test bad arguments properly err:
    assert [
        sogs_put(client, url_room, data, admin).status_code
        for data in (
            {},
            {'name': 42},
            {'name': None},
            {'description': 42},
            {'default_read': "foo"},
            {'default_write': "bar"},
            {'default_upload': None},
        )
    ] == [400] * 7

    assert sogs_get(client, url_room, user).json == expect_room
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}

    # Last but not least let's fill up name and description with emoji!
    emoname = "💰 🐈 🍌 🌋 ‽"
    emodesc = (
        "💾 🚌 🗑 📱 🆗 😴 👖 💲 🍹 📉 🍩 🛎 🚣 ⚫️ 🐕 🕒 🏕 🎩 🆕 🍭 💋 🐌 📡 🚫 "
        "🕢 🚮 🎳 🚠 📦 😛 ♋️ 🌼 🏭 👼 🙆 👗 🏡 😞 🎠 ⭕️ 💚 💁 💸 🌟 ☀️ 🍀 🎶 🍿"
    )
    r = sogs_put(client, url_room, {"description": emodesc, "name": emoname}, admin)
    expect_room['description'] = emodesc
    expect_room['name'] = emoname
    expect_room['info_updates'] += 2

    assert sogs_get(client, url_room, user).json == expect_room
    assert sogs_get(client, url_room, mod).json == {**expect_room, **expect_mod}


def test_polling(client, room, user, user2, mod, admin, global_mod, global_admin):
    r = sogs_get(client, "/room/test-room", user)
    assert r.status_code == 200
    info_up = r.json['info_updates']
    assert info_up == 4

    basic = {'token': 'test-room', 'active_users': 0, 'read': True, 'write': True, 'upload': True}
    details = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 4,
        "message_sequence": 0,
        "created": room.created,
        "active_users": 0,
        "active_users_cutoff": int(sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [mod.session_id],
        "admins": [admin.session_id],
        "read": True,
        "write": True,
        "upload": True,
    }
    defs = {'default_' + x: True for x in ('read', 'accessible', 'write', 'upload')}

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    assert r.json == basic

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    assert r.json == basic

    # We need to call the cleanup handler to update rooms.active_users
    from sogs.cleanup import cleanup

    cleanup()
    basic['active_users'] += 1
    details['active_users'] += 1

    # Make various changes that should each update the room info updates:

    # Changing name
    room.name = 'Test Room'
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['info_updates'] += 1
    details['name'] = 'Test Room'
    assert r.json == {**basic, 'details': details}

    info_up += 1
    cleanup()
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", mod)
    assert r.status_code == 200
    assert r.json == {**basic, 'moderator': True, **defs}

    cleanup()
    basic['active_users'] += 1
    details['active_users'] += 1

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", admin)
    assert r.status_code == 200
    assert r.json == {**basic, 'moderator': True, 'admin': True, **defs}

    cleanup()
    basic['active_users'] += 1
    details['active_users'] += 1

    # Changing description
    room.description = 'Test suite testing room new desc'
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['info_updates'] += 1
    details['description'] = 'Test suite testing room new desc'
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']
    assert 'details' not in sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user).json

    # Setting room image
    tiny_png = (
        b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00'
        b'\x90wS\xde\x00\x00\x00\x0cIDAT\x08\xd7c\x90\x8dp\x04\x00\x01L\x00\xb7\xb1o\xa7\\\x00\x00'
        b'\x00\x00IEND\xaeB`\x82'
    )
    r = sogs_post_raw(
        client,
        f'/room/{room.token}/file',
        tiny_png,
        mod,
        extra_headers={"Content-Disposition": ('attachment', {'filename': 'tiny.png'})},
    )
    assert r.status_code == 201
    assert r.json == {'id': 1}

    img = File(id=r.json['id'])
    assert img.expiry == from_now.hours(1)
    r = sogs_put(client, f'/room/{room.token}', {'image': img.id}, admin)
    assert r.status_code == 200
    assert r.json == {"info_updates": info_up + 1}

    img = File(id=img.id)
    assert img.expiry is None

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['image_id'] = 1
    details['info_updates'] += 1
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    assert 'details' not in sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user).json

    # Add moderator
    room.set_moderator(user, added_by=admin)

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['info_updates'] += 1
    details['moderators'] = sorted(details['moderators'] + [user.session_id])
    assert r.json == {
        **basic,
        **defs,
        'moderator': True,
        'details': {
            **details,
            **defs,
            'default_accessible': True,
            'moderator': True,
            'hidden_admins': [global_admin.session_id],
            'hidden_moderators': [global_mod.session_id],
        },
    }
    info_up += 1
    assert info_up == details['info_updates']

    # Remove moderator
    room.remove_moderator(user, removed_by=admin)
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['info_updates'] += 1
    details['moderators'] = sorted(x for x in details['moderators'] if x != user.session_id)
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    # Add global admin
    user2.set_moderator(added_by=global_admin, admin=True, visible=True)

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['info_updates'] += 1
    details['admins'] = sorted(details['admins'] + [user2.session_id])
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    # Remove global admin
    user2.remove_moderator(removed_by=user2)
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['info_updates'] += 1
    details['admins'] = sorted(x for x in details['admins'] if x != user2.session_id)
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    # Post a message should *not* change info_updates, but should change the message_sequence
    p1 = room.add_post(user, b'fake data', pad64(b'fake sig'))

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    assert 'details' not in r.json

    details['message_sequence'] += 1
    r = sogs_get(client, "/room/test-room", user)
    assert r.json['message_sequence'] == details['message_sequence']

    # Editing also should change message_sequence and not info_updates
    room.edit_post(user, p1['id'], b'more fake data', pad64(b'another fake sig'))
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    assert 'details' not in r.json

    details['message_sequence'] += 1
    r = sogs_get(client, "/room/test-room", user)
    assert r.json['message_sequence'] == details['message_sequence']


def test_fetch_since(client, room, user, no_rate_limit):
    top_fetched = 0
    fetches = 0
    counter = 0  # seqno should follow this
    counts = (1, 1, 1, 2, 0, 3, 0, 0, 5, 7, 11, 12, 0, 25, 0, 101, 0, 203, 0, 100, 200)
    for n in counts:
        for i in range(counter + 1, counter + 1 + n):
            room.add_post(user, f"fake data {i}".encode(), pad64(f"fake sig {i}"))
        counter += n

        done = False
        while not done:
            url = f"/room/test-room/messages/since/{top_fetched}"
            r = sogs_get(client, url, user)
            assert r.status_code == 200
            fetches += 1
            c = min(100, counter - top_fetched)
            assert len(r.json) == c
            for i in range(c):
                post = r.json[i]
                j = top_fetched + 1
                assert set(post.keys()) == {
                    'id',
                    'session_id',
                    'seqno',
                    'data',
                    'signature',
                    'posted',
                    'reactions',
                }
                assert post['session_id'] == user.using_id
                assert post['seqno'] == j
                assert utils.decode_base64(post['data']) == f"fake data {j}".encode()
                assert utils.decode_base64(post['signature']) == pad64(f"fake sig {j}")
                assert post['posted'] == from_now.seconds(0, 10)

                top_fetched = post['seqno']

            assert top_fetched <= counter
            done = len(r.json) < 100

    # Every loop above does one fetch unconditionally, and we require one additional fetch each time
    # we get to 100, 200, etc.
    assert fetches == sum(1 + c // 100 for c in counts)

    # Start over from the beginning, this time using a limit
    done, fetches, top_fetched = False, 0, 0
    while not done:
        url = f"/room/test-room/messages/since/{top_fetched}?limit=25"
        r = sogs_get(client, url, user)
        assert r.status_code == 200
        fetches += 1
        assert [utils.decode_base64(post['data']) for post in r.json] == [
            f'fake data {i}'.encode()
            for i in range(top_fetched + 1, top_fetched + 1 + min(25, len(r.json)))
        ]

        done = len(r.json) < 25
        top_fetched += len(r.json)

    assert fetches == (sum(counts) + 24) // 25


def test_fetch_since_skip_deletions(client, room, user, no_rate_limit):
    # Insert 10 posts; they will have seqno == id (i.e. 1 to 10).
    for i in range(1, 11):
        room.add_post(user, f"fake data {i}".encode(), pad64(f"fake sig {i}"))

    # Delete some:
    deleted = (2, 4, 5, 8, 9)
    for i in deleted:
        r = sogs_delete(client, f'/room/test-room/message/{i}', user)
        assert r.status_code == 200

    def get_and_clean_since(seqno):
        r = sogs_get(client, f"/room/test-room/messages/since/{seqno}", user)
        assert r.status_code == 200
        res = r.json
        for m in res:
            for k in ('posted', 'session_id', 'reactions'):
                if k in m:
                    del m[k]
            for k in ('data', 'signature', 'edited'):
                if k in m and m[k] is not None:
                    m[k] = True
        return res

    # If we poll from 1 we should only see the messages (skipping the first one with seqno=1) that
    # remain (since our polling seqno is before the deleted messages were created in the first
    # place):
    assert get_and_clean_since(1) == [
        {'id': i, 'seqno': i, 'data': True, 'signature': True} for i in (3, 6, 7, 10)
    ]

    def deleted_entry(id, seqno):
        return {'id': id, 'seqno': seqno, 'edited': True, 'deleted': True, 'data': None}

    # If we poll from 2 we should get the deletion for 2, but not the higher deletions
    assert get_and_clean_since(2) == [
        *({'id': i, 'seqno': i, 'data': True, 'signature': True} for i in (3, 6, 7, 10)),
        *(deleted_entry(i, s) for i, s in ((2, 11),)),
    ]

    # From 4 we should get deletions 2 and 4
    assert get_and_clean_since(4) == [
        *({'id': i, 'seqno': i, 'data': True, 'signature': True} for i in (6, 7, 10)),
        *(deleted_entry(i, s) for i, s in ((2, 11), (4, 12))),
    ]

    # and so on
    assert get_and_clean_since(5) == [
        *({'id': i, 'seqno': i, 'data': True, 'signature': True} for i in (6, 7, 10)),
        *(deleted_entry(i, s) for i, s in ((2, 11), (4, 12), (5, 13))),
    ]
    assert get_and_clean_since(6) == [
        *({'id': i, 'seqno': i, 'data': True, 'signature': True} for i in (7, 10)),
        *(deleted_entry(i, s) for i, s in ((2, 11), (4, 12), (5, 13))),
    ]
    assert get_and_clean_since(7) == [
        *({'id': i, 'seqno': i, 'data': True, 'signature': True} for i in (10,)),
        *(deleted_entry(i, s) for i, s in ((2, 11), (4, 12), (5, 13))),
    ]

    assert get_and_clean_since(9) == [
        *({'id': i, 'seqno': i, 'data': True, 'signature': True} for i in (10,)),
        *(deleted_entry(i, s) for i, s in ((2, 11), (4, 12), (5, 13), (8, 14), (9, 15))),
    ]
    assert get_and_clean_since(10) == [
        *(deleted_entry(i, s) for i, s in ((2, 11), (4, 12), (5, 13), (8, 14), (9, 15)))
    ]
    assert get_and_clean_since(11) == [
        *(deleted_entry(i, s) for i, s in ((4, 12), (5, 13), (8, 14), (9, 15)))
    ]
    assert get_and_clean_since(13) == [*(deleted_entry(i, s) for i, s in ((8, 14), (9, 15)))]
    assert get_and_clean_since(14) == [*(deleted_entry(i, s) for i, s in ((9, 15),))]
    assert get_and_clean_since(15) == []


def test_fetch_before(client, room, user, no_rate_limit):
    for i in range(1000):
        room.add_post(user, f"data-{i}".encode(), pad64(f"fake sig {i}"))

    url = "/room/test-room/messages/recent"
    r100 = sogs_get(client, url, user)
    assert len(r100.json) == 100

    assert [p['id'] for p in r100.json] == list(range(1000, 900, -1))

    url = "/room/test-room/messages/recent?limit=201"
    r201 = sogs_get(client, url, user)
    assert len(r201.json) == 201

    assert r100.json == r201.json[:100]

    url = f"/room/test-room/messages/before/{r100.json[-1]['id']}?limit=101"
    r101 = sogs_get(client, url, user)
    assert r101.status_code == 200

    assert r100.json + r101.json == r201.json

    before = r201.json[-1]['id']
    sizes = (45, None, None, 255, None, 100, 1, 98)
    next_exp = before - 1
    for limit in sizes:
        url = f"/room/test-room/messages/before/{before}"
        if limit is not None:
            url = url + f"?limit={limit}"
        else:
            limit = 100
        r = sogs_get(client, url, user)
        assert r.status_code == 200
        assert len(r.json) == limit
        assert r.json[0]['id'] == next_exp
        assert r.json[-1]['id'] == next_exp - limit + 1
        next_exp -= limit
        before = r.json[-1]['id']

    assert next_exp == 0
    assert before == 1
    url = f"/room/test-room/messages/before/{before}"
    r = sogs_get(client, url, user)
    assert len(r.json) == 0


def test_fetch_one(client, room, user, no_rate_limit):
    posts = [room.add_post(user, f"data-{i}".encode(), pad64(f"fake sig {i}")) for i in range(10)]

    for i in (5, 2, 8, 7, 9, 6, 10, 1, 3, 4):
        url = f"/room/test-room/message/{i}"
        r = sogs_get(client, url, user)
        assert r.status_code == 200
        p = posts[i - 1].copy()
        for x in ('data', 'signature'):
            p[x] = utils.encode_base64(p[x])
        assert r.json == p


time_fields = {'posted', 'edited', 'pinned_at', 'at'}


def filter_timestamps(x, fields=time_fields):
    """
    Filters timestamp keys out of a dict or list of dicts (recursively) for easier comparing of
    everything except timestamps.
    """
    if isinstance(x, list):
        return [filter_timestamps(y, fields) for y in x]
    return {
        k: filter_timestamps(v, fields) if isinstance(v, list) or isinstance(v, dict) else v
        for k, v in x.items()
        if k not in fields
    }


def test_pinning(client, room, user, admin, no_rate_limit):
    for i in range(10):
        room.add_post(user, f"data-{i}".encode(), pad64(f"fake sig {i}"))

    def room_json():
        r = sogs_get(client, "/room/test-room", user)
        assert r.status_code == 200
        return r.json

    assert room_json()['info_updates'] == 1

    url = "/room/test-room/pin/3"
    r = sogs_post(client, url, {}, user)
    assert r.status_code == 403

    assert room_json()['info_updates'] == 1

    r = sogs_post(client, url, {}, admin)
    assert r.status_code == 200

    ri = room_json()
    assert ri['info_updates'] == 2
    assert filter_timestamps(ri['pinned_messages']) == [{'id': 3, 'pinned_by': admin.session_id}]
    assert ri['pinned_messages'][0]['pinned_at'] == from_now.now()

    url = "/room/test-room/pin/7"
    r = sogs_post(client, url, {}, admin)
    assert r.status_code == 200
    time.sleep(0.001)
    url = "/room/test-room/pin/5"
    r = sogs_post(client, url, {}, admin)
    assert r.status_code == 200

    ri = room_json()
    assert ri['info_updates'] == 4
    rpm = ri['pinned_messages']

    assert filter_timestamps(ri['pinned_messages']) == [
        {'id': 3, 'pinned_by': admin.session_id},
        {'id': 7, 'pinned_by': admin.session_id},
        {'id': 5, 'pinned_by': admin.session_id},
    ]
    assert (
        time.time() - 1
        < rpm[0]['pinned_at']
        < rpm[1]['pinned_at']
        < rpm[2]['pinned_at']
        < time.time() + 1
    )

    url = "/room/test-room/pin/7"
    r = sogs_post(client, url, {}, admin)
    assert r.status_code == 200

    ri = room_json()
    assert ri['info_updates'] == 5
    rpm = ri['pinned_messages']

    assert filter_timestamps(ri['pinned_messages']) == [
        {'id': 3, 'pinned_by': admin.session_id},
        {'id': 5, 'pinned_by': admin.session_id},
        {'id': 7, 'pinned_by': admin.session_id},
    ]
    assert (
        time.time() - 1
        < rpm[0]['pinned_at']
        < rpm[1]['pinned_at']
        < rpm[2]['pinned_at']
        < time.time() + 1
    )

    url = "/room/test-room/unpin/5"
    r = sogs_post(client, url, {}, admin)
    assert r.status_code == 200

    ri = room_json()
    rpm = ri['pinned_messages']

    assert filter_timestamps(ri['pinned_messages']) == [
        {'id': 3, 'pinned_by': admin.session_id},
        {'id': 7, 'pinned_by': admin.session_id},
    ]
    assert rpm[0]['pinned_at'] == from_now.now()
    assert rpm[0]['pinned_at'] < rpm[1]['pinned_at']
    assert rpm[1]['pinned_at'] == from_now.now()

    url = "/room/test-room/unpin/all"
    r = sogs_post(client, url, {}, admin)
    assert r.status_code == 200

    assert 'pinned_messages' not in room_json()


def test_posting(client, room, user, user2, mod, global_mod):
    url_post = "/room/test-room/message"
    d, s = (utils.encode_base64(x) for x in (b"post 1", pad64("sig 1")))
    r = sogs_post(client, url_post, {"data": d, "signature": s}, user)
    assert r.status_code == 201

    p1 = r.json
    assert filter_timestamps(p1) == {
        'id': 1,
        'seqno': 1,
        'session_id': user.using_id,
        'data': d,
        'signature': s,
        'reactions': {},
    }
    assert p1['posted'] == from_now.now()

    url_get = "/room/test-room/messages/since/0"
    r = sogs_get(client, url_get, user)
    assert r.json == [p1]


def test_whisper_to(client, room, user, user2, mod, global_mod):
    url_post = "/room/test-room/message"
    d, s = (utils.encode_base64(x) for x in (b"whisper 1", pad64("sig 1")))
    p = {"data": d, "signature": s, "whisper_to": user2.session_id}

    # Regular users can't post whispers:
    r = sogs_post(client, url_post, p, user)
    assert r.status_code == 403

    r = sogs_post(client, url_post, p, mod)
    assert r.status_code == 201
    msg = r.json
    assert filter_timestamps(msg) == {
        'id': 1,
        'seqno': 1,
        'session_id': mod.using_id,
        'data': d,
        'signature': s,
        'whisper': True,
        'whisper_mods': False,
        'whisper_to': user2.session_id,
        'reactions': {},
    }
    assert msg['posted'] == from_now.now()

    url_get = "/room/test-room/messages/since/0"
    # user shouldn't get the whisper:
    r = sogs_get(client, url_get, user)
    assert r.status_code == 200
    assert filter_timestamps(r.json) == filter_timestamps([])

    # user2 should get it:
    r = sogs_get(client, url_get, user2)
    assert r.status_code == 200
    assert filter_timestamps(r.json) == filter_timestamps([msg])

    # The mod who sent it should still see it (even though not directed at mods):
    r = sogs_get(client, url_get, mod)
    assert r.status_code == 200
    assert filter_timestamps(r.json) == filter_timestamps([msg])

    # another mod shouldn't get it
    r = sogs_get(client, url_get, global_mod)
    assert r.status_code == 200
    assert filter_timestamps(r.json) == filter_timestamps([])


def test_whisper_mods(client, room, user, user2, mod, global_mod, admin):
    url_post = "/room/test-room/message"
    d, s = (utils.encode_base64(x) for x in (b"whisper 1", pad64("sig 1")))
    p = {"data": d, "signature": s, "whisper_mods": True}

    # Regular users can't post mod whispers:
    r = sogs_post(client, url_post, p, user)
    assert r.status_code == 403

    r = sogs_post(client, url_post, p, mod)
    assert r.status_code == 201
    msg = r.json
    assert filter_timestamps(msg) == {
        'id': 1,
        'seqno': 1,
        'session_id': mod.using_id,
        'data': d,
        'signature': s,
        'whisper': True,
        'whisper_mods': True,
        'reactions': {},
    }
    assert msg['posted'] == from_now.now()

    url_get = "/room/test-room/messages/since/0"

    # users shouldn't get the whisper:
    for u in (user, user2):
        r = sogs_get(client, url_get, u)
        assert r.status_code == 200
        assert filter_timestamps(r.json) == filter_timestamps([])

    # All mods/admins should get it
    for m in (mod, global_mod, admin):
        r = sogs_get(client, url_get, mod)
        assert r.status_code == 200
        assert filter_timestamps(r.json) == filter_timestamps([msg])


def test_whisper_both(client, room, user, user2, mod, admin):
    # A whisper aimed at both a user *and* all mods (e.g. a warning to a user)

    url_post = "/room/test-room/message"
    d, s = (utils.encode_base64(x) for x in (b"offensive post!", pad64("sig")))
    p = {"data": d, "signature": s}
    r = sogs_post(client, url_post, p, user)
    assert r.status_code == 201
    msg = r.json
    assert filter_timestamps(msg) == {
        'id': 1,
        'seqno': 1,
        'session_id': user.using_id,
        'data': d,
        'signature': s,
        'reactions': {},
    }

    # Regular users can't post mod whispers:
    p = {"data": d, "signature": s, "whisper_mods": True, "whisper_to": mod.session_id}
    r = sogs_post(client, url_post, p, user)
    assert r.status_code == 403

    d, s = (utils.encode_base64(x) for x in (b"I'm going to scare this guy", pad64("sig2")))
    r = sogs_post(client, url_post, {"data": d, "signature": s, "whisper_mods": True}, mod)
    assert r.status_code == 201
    w1 = r.json

    d, s = (utils.encode_base64(x) for x in (b"WTF, do you want a ban?", pad64("sig3")))
    p = {"data": d, "signature": s, "whisper_to": user.session_id, "whisper_mods": True}
    r = sogs_post(client, url_post, p, mod)
    w2 = r.json

    d, s = (utils.encode_base64(x) for x in (b"No please I'm sorry!!!", pad64("sig4")))
    r = sogs_post(client, url_post, {"data": d, "signature": s}, user)
    msg2 = r.json

    assert filter_timestamps([msg, w1, w2, msg2]) == [
        {
            'id': 1,
            'seqno': 1,
            'session_id': user.using_id,
            'data': utils.encode_base64('offensive post!'.encode()),
            'signature': utils.encode_base64(pad64('sig')),
            'reactions': {},
        },
        {
            'id': 2,
            'seqno': 2,
            'session_id': mod.using_id,
            'data': utils.encode_base64("I'm going to scare this guy".encode()),
            'signature': utils.encode_base64(pad64('sig2')),
            'whisper': True,
            'whisper_mods': True,
            'reactions': {},
        },
        {
            'id': 3,
            'seqno': 3,
            'session_id': mod.using_id,
            'data': utils.encode_base64("WTF, do you want a ban?".encode()),
            'signature': utils.encode_base64(pad64('sig3')),
            'whisper': True,
            'whisper_mods': True,
            'whisper_to': user.session_id,
            'reactions': {},
        },
        {
            'id': 4,
            'seqno': 4,
            'session_id': user.using_id,
            'data': utils.encode_base64("No please I'm sorry!!!".encode()),
            'signature': utils.encode_base64(pad64('sig4')),
            'reactions': {},
        },
    ]

    url_get = "/room/test-room/messages/since/0"

    r = sogs_get(client, url_get, user)
    assert r.json == [msg, w2, msg2]

    r = sogs_get(client, url_get, user2)
    assert r.json == [msg, msg2]

    r = sogs_get(client, url_get, mod)
    assert r.json == [msg, w1, w2, msg2]

    r = sogs_get(client, url_get, admin)
    assert r.json == [msg, w1, w2, msg2]


def test_edits(client, room, user, user2, mod, global_admin):
    url_post = "/room/test-room/message"
    d, s = (utils.encode_base64(x) for x in (b"post 1", pad64("sig 1")))
    r = sogs_post(client, url_post, {"data": d, "signature": s}, user)
    assert r.status_code == 201

    p1 = r.json
    assert filter_timestamps(p1) == {
        'id': 1,
        'seqno': 1,
        'session_id': user.using_id,
        'data': d,
        'signature': s,
        'reactions': {},
    }
    assert p1['posted'] == from_now.now()

    url_get = "/room/test-room/messages/since/0"
    r = sogs_get(client, url_get, user)
    assert r.json == [p1]

    url_edit = "/room/test-room/message/1"

    # Make sure someone else (even super admin) can't edit our message:
    d, s = (utils.encode_base64(x) for x in (b"post 1no", pad64("sig 1no")))
    r = sogs_put(client, url_edit, {"data": d, "signature": s}, global_admin)
    assert r.status_code == 403

    r = sogs_get(client, url_get, user)
    assert filter_timestamps(r.json) == filter_timestamps([p1])
    assert 'edited' not in r.json[0]

    d, s = (utils.encode_base64(x) for x in (b"post 1b", pad64("sig 1b")))
    time.sleep(0.001)
    r = sogs_put(client, url_edit, {"data": d, "signature": s}, user)
    assert r.status_code == 200
    assert r.json == {}
    p1['seqno'] = 2
    p1['data'] = d
    p1['signature'] = s

    r = sogs_get(client, url_get, user)
    assert filter_timestamps(r.json) == filter_timestamps([p1])
    assert r.json[0]['posted'] == from_now.now()
    assert r.json[0]['posted'] < r.json[0]['edited']
    assert r.json[0]['edited'] == from_now.now()
    p1['edited'] = r.json[0]['edited']

    d, s = (utils.encode_base64(x) for x in (b"post 2", pad64("sig 2")))
    r = sogs_post(client, url_post, {"data": d, "signature": s}, user2)
    assert r.status_code == 201
    p2 = r.json
    assert filter_timestamps(p2) == {
        'id': 2,
        'seqno': 3,
        'session_id': user2.using_id,
        'data': d,
        'signature': s,
        'reactions': {},
    }
    assert p2['posted'] == from_now.now()

    d, s = (utils.encode_base64(x) for x in (b"post 1c", pad64("sig 1c")))
    time.sleep(0.001)
    r = sogs_put(client, url_edit, {"data": d, "signature": s}, user)
    assert r.status_code == 200
    assert r.json == {}
    p1['seqno'] = 4
    p1['data'] = d
    p1['signature'] = s

    url_get = "/room/test-room/messages/since/3"
    r = sogs_get(client, url_get, user2)
    assert (
        time.time() - 1
        < r.json[0]['posted']
        == p1['posted']
        < p1['edited']
        < r.json[0]['edited']
        < time.time() + 1
    )
    p1['edited'] = r.json[0]['edited']
    assert r.json == [p1]

    url_get = "/room/test-room/messages/since/0"
    r = sogs_get(client, url_get, mod)
    assert r.json == [p2, p1]

    url_get = "/room/test-room/messages/since/1"
    r = sogs_get(client, url_get, global_admin)
    assert r.json == [p2, p1]

    url_get = "/room/test-room/messages/since/2"
    r = sogs_get(client, url_get, user)
    assert r.json == [p2, p1]

    url_get = "/room/test-room/messages/since/4"
    r = sogs_get(client, url_get, user)
    assert r.json == []


def _make_dummy_post(room, user):
    msg = room.add_post(user, b'data', b'a' * 64)
    return msg.get('id')


def test_remove_message(client, room, mod, user):
    id = _make_dummy_post(room, user)
    r = sogs_delete(client, f'/room/{room.token}/message/{id}', mod)
    assert r.status_code == 200


def test_remove_self_message(client, room, user):
    id = _make_dummy_post(room, user)
    r = sogs_delete(client, f'/room/{room.token}/message/{id}', user)
    assert r.status_code == 200


def test_remove_message_not_allowed(client, room, user, user2):
    id = _make_dummy_post(room, user)
    r = sogs_delete(client, f'/room/{room.token}/message/{id}', user2)
    assert r.status_code == 403


def test_remove_post_non_existing(client, room, user, mod):
    r = sogs_delete(client, f'/room/{room.token}/message/10000', user)
    assert r.status_code == 404
    r = sogs_delete(client, f'/room/{room.token}/message/10000', mod)
    assert r.status_code == 404


def test_remove_post_non_existing_banned_user(client, room, banned_user):
    r = sogs_delete(client, f'/room/{room.token}/message/10000', banned_user)
    assert r.status_code == 403


def test_remove_self_post_banned_user(client, room, user, mod):
    id = _make_dummy_post(room, user)
    room.ban_user(user, mod=mod)
    r = sogs_delete(client, f'/room/{room.token}/message/{id}', user)
    assert r.status_code == 403


def test_remove_all_posts_from_room(client, room, user, mod, no_rate_limit):
    for _ in range(256):
        _make_dummy_post(room, user)
    assert len(room.get_messages_for(user, recent=True)) == 256
    r = sogs_delete(client, f'/room/{room.token}/all/{user.session_id}', mod)
    assert r.status_code == 200
    assert len(room.get_messages_for(user, recent=True)) == 0
    assert room.check_unbanned(user)


def test_remove_all_posts_from_room_not_allowed(client, room, user, user2, no_rate_limit):
    for _ in range(256):
        _make_dummy_post(room, user)
    assert len(room.get_messages_for(user, recent=True)) == 256
    r = sogs_delete(client, f'/room/{room.token}/all/{user.session_id}', user2)
    assert r.status_code == 403
    assert len(room.get_messages_for(user, recent=True)) == 256
    assert room.check_unbanned(user) and room.check_unbanned(user2)


def test_remove_all_posts_from_room_not_allowed_for_user(client, room, mod, user, no_rate_limit):
    for _ in range(256):
        _make_dummy_post(room, mod)
    r = sogs_delete(client, f'/room/{room.token}/all/{mod.session_id}', user)
    assert r.status_code == 403
    assert len(room.get_messages_for(user, recent=True)) == 256
    assert room.check_unbanned(user) and room.check_unbanned(mod)


def test_remove_all_self_posts_from_room(client, room, mod, user, no_rate_limit):
    for u in (user, mod):
        for _ in range(256):
            _make_dummy_post(room, u)
        assert len(room.get_messages_for(u, recent=True)) == 256
        r = sogs_delete(client, f'/room/{room.token}/all/{u.session_id}', u)
        assert r.status_code == 200
        assert len(room.get_messages_for(u, recent=True)) == 0
        assert room.check_unbanned(u)


def test_get_room_perms(client, room, user):
    r = sogs_get(client, f'/room/{room.token}/permissions', user)
    assert r.status_code == 403


def test_get_room_perms_as_mod(client, room, mod):
    r = sogs_get(client, f'/room/{room.token}/permissions', mod)
    assert r.status_code == 200
    assert mod.session_id in r.json
    perm_info = r.json[mod.session_id]
    assert perm_info['moderator'] is True


def test_get_room_perms_as_admin(client, room, admin):
    r = sogs_get(client, f'/room/{room.token}/permissions', admin)
    assert r.status_code == 200
    assert admin.session_id in r.json
    perm_info = r.json[admin.session_id]
    assert perm_info['admin'] is True


def test_get_room_future_perms(client, room, mod):
    r = sogs_get(client, f'/room/{room.token}/futurePermissions', mod)
    assert r.status_code == 200
    assert r.json == []


def test_get_room_future_perms_not_allowed(client, room, user):
    r = sogs_get(client, f'/room/{room.token}/futurePermissions', user)
    assert r.status_code == 403


def test_set_room_perms(client, room, user, mod):
    r = sogs_post(
        client,
        f'/room/{room.token}/permissions/{user.session_id}',
        {'read': True, 'write': False},
        mod,
    )

    assert r.status_code == 200
    assert r.json == {"read": True, "write": False}

    r = sogs_post(
        client, f'/room/{room.token}/permissions/{user.session_id}', {'default_read': True}, mod
    )
    assert r.status_code == 200
    assert r.json == {"write": False}

    r = sogs_post(
        client,
        f'/room/{room.token}/permissions/{user.session_id}',
        {'default_read': True, 'write': False, 'upload': False, 'accessible': True},
        mod,
    )
    assert r.status_code == 200
    assert r.json == {"write": False, 'upload': False, 'accessible': True}

    r = sogs_get(client, f'/room/{room.token}/permissions', mod)
    assert r.status_code == 200
    assert r.json == {
        mod.session_id: {'moderator': True},
        user.session_id: {"write": False, 'upload': False, 'accessible': True},
    }

    r = sogs_get(client, f'/room/{room.token}/permissions/{user.session_id}', mod)
    assert r.status_code == 200
    assert r.json == {"write": False, "upload": False, "accessible": True}

    r = sogs_post(
        client,
        f'/room/{room.token}/permissions/{user.session_id}',
        {'default_' + x: True for x in ('read', 'write', 'upload', 'accessible')},
        mod,
    )
    assert r.status_code == 200
    assert r.json == {}


def test_set_room_perm_futures(client, room, user, mod):
    r = sogs_post(
        client,
        '/sequence',
        [
            {
                'method': 'POST',
                'path': f'/room/{room.token}/permissions/{user.session_id}',
                'json': {'read': True, 'write': False, 'upload': False, 'accessible': True},
            },
            {
                'method': 'POST',
                'path': f'/room/{room.token}/futurePermissions/{user.session_id}',
                'json': {'write': True, 'upload': True, 'in': 0.001},
            },
        ],
        mod,
    )
    assert filter_timestamps(r.json) == [
        {
            'code': 200,
            'headers': {'content-type': 'application/json'},
            'body': {'read': True, 'write': False, 'upload': False, 'accessible': True},
        },
        {
            "code": 200,
            'headers': {'content-type': 'application/json'},
            'body': [{'upload': True, 'write': True}],
        },
    ]

    assert r.json[1]['body'][0]['at'] == from_now.seconds(0.001)
    time.sleep(0.002)

    r = sogs_get(client, f'/room/{room.token}/futurePermissions', mod)
    assert r.status_code == 200
    assert filter_timestamps(r.json) == [
        {'session_id': user.session_id, 'upload': True, 'write': True}
    ]
    assert r.json[0]['at'] == from_now.seconds(0.001)

    r = sogs_post(
        client,
        f'/room/{room.token}/futurePermissions/{user.session_id}',
        {'in': 30, 'write': False, 'upload': False, 'read': False},
        mod,
    )
    assert r.status_code == 200
    assert filter_timestamps(r.json) == [
        {'upload': True, 'write': True},
        {'upload': False, 'write': False, 'read': False},
    ]
    assert r.json[0]['at'] == from_now.seconds(0.001)
    assert r.json[1]['at'] == from_now.seconds(30)

    from sogs.cleanup import cleanup

    assert cleanup() == (0, 0, 0, 1, 0)

    r = sogs_get(client, f'/room/{room.token}/permissions/{user.session_id}', mod)
    assert r.status_code == 200
    assert r.json == {'read': True, 'accessible': True}

    r = sogs_get(client, f'/room/{room.token}/futurePermissions/{user.session_id}', mod)
    assert r.status_code == 200
    assert filter_timestamps(r.json) == [{'upload': False, 'write': False, 'read': False}]
    assert r.json[0]['at'] == from_now.seconds(29.999)

    r = sogs_get(client, f'/room/{room.token}/permissions', mod)
    assert r.status_code == 200
    assert r.json == {
        user.session_id: {'read': True, 'accessible': True},
        mod.session_id: {'moderator': True},
    }

    r = sogs_get(client, f'/room/{room.token}/futurePermissions', mod)
    assert r.status_code == 200
    assert filter_timestamps(r.json) == [
        {'session_id': user.session_id, 'upload': False, 'write': False, 'read': False}
    ]
    assert r.json[0]['at'] == from_now.seconds(29.999)

    r = sogs_get(client, f'/room/{room.token}/permissions/{user.session_id}', user)
    assert r.status_code == 403
    r = sogs_get(client, f'/room/{room.token}/futurePermissions/{user.session_id}', user)
    assert r.status_code == 403


def test_set_room_perms_blinding(client, db, room, user, user2, mod):
    with config_override(REQUIRE_BLIND_KEYS=True):
        db.database_init()

        # Authenticate `user` so that the sogs knows about user's session id before we set up
        # permissions (to make sure they go to the *blinded* id even when we specify the unblinded
        # id):
        r = client.get(
            f'/room/{room.token}',
            headers=x_sogs(
                user.ed_key, crypto.server_pubkey, 'GET', f'/room/{room.token}', blinded15=True
            ),
        )
        assert r.status_code == 200

        body = json.dumps(
            [
                {
                    'method': 'POST',
                    'path': f'/room/{room.token}/permissions/{user.session_id}',
                    'json': {'read': True, 'write': False},
                },
                {
                    'method': 'POST',
                    'path': f'/room/{room.token}/futurePermissions/{user.session_id}',
                    'json': {'write': True, 'in': 0.001},
                },
                {
                    'method': 'POST',
                    'path': f'/room/{room.token}/permissions/{user2.session_id}',
                    'json': {'upload': False},
                },
                {
                    'method': 'POST',
                    'path': f'/room/{room.token}/futurePermissions/{user2.session_id}',
                    'json': {'upload': True, 'in': 0.002},
                },
            ]
        ).encode()
        r = client.post(
            '/sequence',
            headers=x_sogs(
                mod.ed_key, crypto.server_pubkey, 'POST', '/sequence', body, blinded15=True
            ),
            content_type='application/json',
            data=body,
        )
        assert r.status_code == 200
        assert filter_timestamps(r.json) == [
            {
                'code': 200,
                'headers': {'content-type': 'application/json'},
                'body': {'read': True, 'write': False},
            },
            {
                "code": 200,
                'headers': {'content-type': 'application/json'},
                'body': [{'write': True}],
            },
            {
                'code': 200,
                'headers': {'content-type': 'application/json'},
                'body': {'upload': False},
            },
            {
                "code": 200,
                'headers': {'content-type': 'application/json'},
                'body': [{'upload': True}],
            },
        ]

        assert r.json[1]['body'][0]['at'] == from_now.seconds(0.001)
        assert r.json[3]['body'][0]['at'] == from_now.seconds(0.002)

        r = client.get(
            f'/room/{room.token}/permissions',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/permissions',
                blinded15=True,
            ),
        )
        assert r.status_code == 200
        assert r.json == {
            # all users are 25-blinded in the database now
            user.blinded25_id: {'read': True, 'write': False},
            user2.blinded25_id: {'upload': False},
            mod.blinded25_id: {'moderator': True},
        }

        r = client.get(
            f'/room/{room.token}/futurePermissions',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/futurePermissions',
                blinded15=True,
            ),
        )
        assert r.status_code == 200
        assert filter_timestamps(r.json) == [
            {'session_id': user.blinded25_id, 'write': True},
            {'session_id': user2.blinded25_id, 'upload': True},
        ]
        assert r.json[0]['at'] == from_now.seconds(0.001)
        assert r.json[1]['at'] == from_now.seconds(0.002)

        # Authenticate user2, which should auto-convert the unblinded perm and future to the blinded
        # id:
        r = client.get(
            f'/room/{room.token}',
            headers=x_sogs(
                user2.ed_key, crypto.server_pubkey, 'GET', f'/room/{room.token}', blinded15=True
            ),
        )
        assert r.status_code == 200

        r = client.get(
            f'/room/{room.token}/permissions',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/permissions',
                blinded15=True,
            ),
        )
        assert r.status_code == 200
        assert r.json == {
            user.blinded25_id: {'read': True, 'write': False},
            user2.blinded25_id: {'upload': False},
            mod.blinded25_id: {'moderator': True},
        }

        r = client.get(
            f'/room/{room.token}/futurePermissions',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/futurePermissions',
                blinded15=True,
            ),
        )
        assert r.status_code == 200
        assert filter_timestamps(r.json) == [
            {'session_id': user.blinded25_id, 'write': True},
            {'session_id': user2.blinded25_id, 'upload': True},
        ]
        assert r.json[0]['at'] == from_now.seconds(0.001)
        assert r.json[1]['at'] == from_now.seconds(0.002)

        # GETting either blinded or unblinded should give us back the same permissions:
        r = client.get(
            f'/room/{room.token}/permissions/{user.session_id}',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/permissions/{user.session_id}',
                blinded15=True,
            ),
        )
        assert r.status_code == 200
        assert r.json == {'read': True, 'write': False}
        r2 = client.get(
            f'/room/{room.token}/permissions/{user.blinded15_id}',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/permissions/{user.blinded15_id}',
                blinded15=True,
            ),
        )
        assert r2.status_code == 200
        assert r2.json == r.json

        r = client.get(
            f'/room/{room.token}/futurePermissions/{user2.session_id}',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/futurePermissions/{user2.session_id}',
                blinded15=True,
            ),
        )
        assert r.status_code == 200
        assert filter_timestamps(r.json) == [{'upload': True}]
        assert r.json[0]['at'] == from_now.seconds(0.002)
        r2 = client.get(
            f'/room/{room.token}/futurePermissions/{user2.blinded15_id}',
            headers=x_sogs(
                mod.ed_key,
                crypto.server_pubkey,
                'GET',
                f'/room/{room.token}/futurePermissions/{user2.blinded15_id}',
                blinded15=True,
            ),
        )
        assert r2.status_code == 200
        assert r2.json == r.json
