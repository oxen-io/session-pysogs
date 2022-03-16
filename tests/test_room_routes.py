import pytest
import time
from sogs.model.room import Room
from sogs.model.file import File
from sogs import utils
import sogs.config
import werkzeug.exceptions as wexc
from werkzeug.http import parse_options_header
from util import pad64, from_now
from request import sogs_get, sogs_post, sogs_put, sogs_post_raw, sogs_delete
from nacl.utils import random
from os import path
from random import Random
import urllib
import re


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
        "info_updates": 0,
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
        "info_updates": 2,
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


def test_updates(client, room, user, user2, mod, admin, global_mod, global_admin):
    url_room = '/room/test-room'
    r = sogs_get(client, url_room, user)
    assert r.status_code == 200
    expect_room = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 2,
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
    assert info_up == 2

    basic = {'token': 'test-room', 'active_users': 1, 'read': True, 'write': True, 'upload': True}
    details = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 2,
        "message_sequence": 0,
        "created": room.created,
        "active_users": 1,
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

    # Make various changes that should each update the room info updates:

    # Changing name
    room.name = 'Test Room'
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", user)
    assert r.status_code == 200
    details['info_updates'] += 1
    details['name'] = 'Test Room'
    assert r.json == {**basic, 'details': details}

    info_up += 1
    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", mod)
    basic['active_users'] += 1
    details['active_users'] += 1
    assert r.status_code == 200
    assert r.json == {**basic, 'moderator': True, **defs}

    r = sogs_get(client, f"/room/test-room/pollInfo/{info_up}", admin)
    assert r.status_code == 200
    basic['active_users'] += 1
    details['active_users'] += 1
    assert r.json == {**basic, 'moderator': True, 'admin': True, **defs}

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
    assert r.json == dict()
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
                }
                assert post['session_id'] == user.session_id
                assert post['seqno'] == j
                assert utils.decode_base64(post['data']) == f"fake data {j}".encode()
                assert utils.decode_base64(post['signature']) == pad64(f"fake sig {j}")
                assert -10 <= post['posted'] - time.time() <= 10

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


time_fields = {'posted', 'edited', 'pinned_at'}


def filter_timestamps(x, fields=time_fields):
    """Filters timestamp fields out of a dict or list of dicts for easier comparing of everything
    except timestamps"""
    if isinstance(x, list):
        return [filter_timestamps(y, fields) for y in x]
    return {k: v for k, v in x.items() if k not in fields}


def test_pinning(client, room, user, admin, no_rate_limit):
    for i in range(10):
        room.add_post(user, f"data-{i}".encode(), pad64(f"fake sig {i}"))

    def room_json():
        r = sogs_get(client, "/room/test-room", user)
        assert r.status_code == 200
        return r.json

    assert room_json()['info_updates'] == 1

    url = "/room/test-room/pin/3"
    with pytest.raises(wexc.Forbidden):
        r = sogs_post(client, url, {}, user)

    assert room_json()['info_updates'] == 1

    r = sogs_post(client, url, {}, admin)
    assert r.status_code == 200

    ri = room_json()
    assert ri['info_updates'] == 2
    assert filter_timestamps(ri['pinned_messages']) == [{'id': 3, 'pinned_by': admin.session_id}]
    assert -1 < ri['pinned_messages'][0]['pinned_at'] - time.time() < 1

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
    assert time.time() - 1 < rpm[0]['pinned_at'] < rpm[1]['pinned_at'] < time.time() + 1

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
        'session_id': user.session_id,
        'data': d,
        'signature': s,
    }
    assert -1 < p1['posted'] - time.time() < 1

    url_get = "/room/test-room/messages/since/0"
    r = sogs_get(client, url_get, user)
    assert r.json == [p1]


def test_whisper_to(client, room, user, user2, mod, global_mod):

    url_post = "/room/test-room/message"
    d, s = (utils.encode_base64(x) for x in (b"whisper 1", pad64("sig 1")))
    p = {"data": d, "signature": s, "whisper_to": user2.session_id}

    # Regular users can't post whispers:
    with pytest.raises(wexc.Forbidden):
        r = sogs_post(client, url_post, p, user)

    r = sogs_post(client, url_post, p, mod)
    assert r.status_code == 201
    msg = r.json
    assert filter_timestamps(msg) == {
        'id': 1,
        'seqno': 1,
        'session_id': mod.session_id,
        'data': d,
        'signature': s,
        'whisper': True,
        'whisper_mods': False,
        'whisper_to': user2.session_id,
    }
    assert -1 < msg['posted'] - time.time() < 1

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
    with pytest.raises(wexc.Forbidden):
        r = sogs_post(client, url_post, p, user)

    r = sogs_post(client, url_post, p, mod)
    assert r.status_code == 201
    msg = r.json
    assert filter_timestamps(msg) == {
        'id': 1,
        'seqno': 1,
        'session_id': mod.session_id,
        'data': d,
        'signature': s,
        'whisper': True,
        'whisper_mods': True,
    }
    assert -1 < msg['posted'] - time.time() < 1

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
        'session_id': user.session_id,
        'data': d,
        'signature': s,
    }

    # Regular users can't post mod whispers:
    with pytest.raises(wexc.Forbidden):
        p = {"data": d, "signature": s, "whisper_mods": True, "whisper_to": mod.session_id}
        r = sogs_post(client, url_post, p, user)

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
            'session_id': user.session_id,
            'data': utils.encode_base64('offensive post!'.encode()),
            'signature': utils.encode_base64(pad64('sig')),
        },
        {
            'id': 2,
            'seqno': 2,
            'session_id': mod.session_id,
            'data': utils.encode_base64("I'm going to scare this guy".encode()),
            'signature': utils.encode_base64(pad64('sig2')),
            'whisper': True,
            'whisper_mods': True,
        },
        {
            'id': 3,
            'seqno': 3,
            'session_id': mod.session_id,
            'data': utils.encode_base64("WTF, do you want a ban?".encode()),
            'signature': utils.encode_base64(pad64('sig3')),
            'whisper': True,
            'whisper_mods': True,
            'whisper_to': user.session_id,
        },
        {
            'id': 4,
            'seqno': 4,
            'session_id': user.session_id,
            'data': utils.encode_base64("No please I'm sorry!!!".encode()),
            'signature': utils.encode_base64(pad64('sig4')),
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
        'session_id': user.session_id,
        'data': d,
        'signature': s,
    }
    assert -1 < p1['posted'] - time.time() < 1

    url_get = "/room/test-room/messages/since/0"
    r = sogs_get(client, url_get, user)
    assert r.json == [p1]

    url_edit = "/room/test-room/message/1"

    # Make sure someone else (even super admin) can't edit our message:
    d, s = (utils.encode_base64(x) for x in (b"post 1no", pad64("sig 1no")))
    with pytest.raises(wexc.Forbidden):
        r = sogs_put(client, url_edit, {"data": d, "signature": s}, global_admin)

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
    assert time.time() - 1 < r.json[0]['posted'] < r.json[0]['edited'] < time.time() + 1
    p1['edited'] = r.json[0]['edited']

    d, s = (utils.encode_base64(x) for x in (b"post 2", pad64("sig 2")))
    r = sogs_post(client, url_post, {"data": d, "signature": s}, user2)
    assert r.status_code == 201
    p2 = r.json
    assert filter_timestamps(p2) == {
        'id': 2,
        'seqno': 3,
        'session_id': user2.session_id,
        'data': d,
        'signature': s,
    }
    assert -1 < p2['posted'] - time.time() < 1

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


def _make_file_upload(filename):
    return random(1024), {"Content-Disposition": ('attachment', {'filename': filename})}


def test_owned_files(client, room, room2, user, admin):
    # - upload a file via new endpoints
    filedata, headers = _make_file_upload('fug-1.jpeg')
    r = sogs_post_raw(client, f'/room/{room.token}/file', filedata, user, extra_headers=headers)
    assert r.status_code == 201
    assert 'id' in r.json
    f1 = File(id=r.json.get('id'))
    # - verify that the file expiry is 1h from now (±1s)
    assert f1.expiry == from_now.hours(1)
    # - add a post that references the file
    d, s = (utils.encode_base64(x) for x in (b"post data", pad64("fugg")))
    post_info = {'data': d, 'signature': s, 'files': [f1.id]}
    r = sogs_post(client, f'/room/{room.token}/message', post_info, user)
    assert r.status_code == 201
    assert 'id' in r.json
    post_id = r.json.get('id')
    # - verify that the file expiry is 15 days from now (±1s)
    f1 = File(id=f1.id)
    assert f1.expiry == from_now.days(15)
    # - verify that the file is correctly associated with the post
    assert f1.post_id == post_id

    # - upload another file
    filedata, headers = _make_file_upload('fug-2.jpeg')
    r = sogs_post_raw(client, f'/room/{room.token}/file', filedata, user, extra_headers=headers)
    assert r.status_code == 201
    assert 'id' in r.json
    f2 = File(id=r.json.get('id'))
    # - verify the new file exp is ~1h
    assert f2.expiry == from_now.hours(1)
    # - edit the post with the edit referencing both files
    d, s = (utils.encode_base64(x) for x in (b"better post data", pad64("fugg")))
    new_post_info = {'data': d, 'signature': s, 'files': [f2.id]}
    r = sogs_put(client, f'/room/{room.token}/message/{post_id}', new_post_info, user)
    assert r.status_code == 200
    # - verify the new file exp is ~15 days
    f2 = File(id=f2.id)
    assert f2.expiry == from_now.days(15)
    # - verify that the second file is correctly associated with the post
    assert f2.post_id == post_id
    # - verify that the old file exp hasn't changed
    f1 = File(id=f1.id)
    assert f1.expiry == from_now.days(15)
    # - pin the post
    room.pin(post_id, admin)
    # - verify that expiry of both files is now NULL
    f1 = File(id=f1.id)
    f2 = File(id=f2.id)
    assert f1.expiry is None and f2.expiry is None
    # - unpin the post
    room.unpin(post_id, admin)
    # - verify that expiry of both is reset to 15d
    f1 = File(id=f1.id)
    f2 = File(id=f2.id)
    assert (f1.expiry, f2.expiry) == (from_now.days(15), from_now.days(15))

    # - make another post that references one of the first post's file
    filedata, headers = _make_file_upload('another.png')
    r = sogs_post_raw(client, f'/room/{room.token}/file', filedata, user, extra_headers=headers)
    assert r.status_code == 201
    f3 = File(id=r.json['id'])
    assert f3.expiry == from_now.hours(1)
    d, s = (utils.encode_base64(x) for x in (b"more post data", pad64("fsdf")))
    post_info = {'data': d, 'signature': s, 'files': [f1.id, f3.id]}
    r = sogs_put(client, f'/room/{room.token}/message/{post_id}', post_info, user)
    assert r.status_code == 200
    f3 = File(id=f3.id)
    assert f3.expiry == from_now.days(15)

    # - make sure the first post associated message hasn't changed (i.e. no stealing owned uploads)
    f1a = File(id=f1.id)
    assert f1a.expiry == f1.expiry and f1a.post_id == post_id

    # - upload a file and set it as the room image
    filedata, headers = _make_file_upload('room-image.png')
    r = sogs_post_raw(client, f'/room/{room.token}/file', filedata, user, extra_headers=headers)
    room_img = r.json['id']
    assert r.status_code == 201
    r = sogs_put(client, f'/room/{room.token}', {'image': room_img}, admin)
    assert r.status_code == 200

    # - verify that the uploaded file expiry and message are both NULL
    f_room = File(id=room_img)
    assert f_room.post_id is None
    assert f_room.expiry is None

    # - make a post referencing the room image ID
    d, s = (utils.encode_base64(x) for x in (b"post xyz", pad64("z")))
    post_info = {'data': d, 'signature': s, 'files': [room_img]}
    r = sogs_put(client, f'/room/{room.token}/message/{post_id}', post_info, user)
    assert r.status_code == 200

    # - verify that the pinned image expiry and message are still both NULL
    f_room = File(id=f_room.id)
    assert f_room.post_id is None
    assert f_room.expiry is None

    # - delete the first post
    r = sogs_delete(client, f'/room/{room.token}/message/{post_id}', user)
    assert r.status_code == 200

    # - verify that both attachments are now expired
    f1 = File(id=f1.id)
    f2 = File(id=f2.id)
    assert (f1.expiry, f2.expiry) == (0.0, 0.0)

    from sogs.cleanup import cleanup

    # Cleanup should remove 3 attachments: the two originals plus the one we added via an edit:
    assert cleanup() == (3, 0, 0, 0, 0)

    with pytest.raises(sogs.model.exc.NoSuchFile):
        f1 = File(id=f1.id)
    with pytest.raises(sogs.model.exc.NoSuchFile):
        f2 = File(id=f2.id)


def test_no_file_crosspost(client, room, room2, user, global_admin):
    # Disallow cross-room references (i.e. a post attaching a file uploaded to another room)
    filedata, headers = _make_file_upload('room2-file.jpg')
    r = sogs_post_raw(client, f'/room/{room2.token}/file', filedata, user, extra_headers=headers)
    assert r.status_code == 201
    f = File(id=r.json['id'])
    d, s = (utils.encode_base64(x) for x in (b"room1 post", pad64("sig123")))
    post_info = {'data': d, 'signature': s, 'files': [f.id]}
    r = sogs_post(client, f'/room/{room.token}/message', post_info, user)
    assert r.status_code == 201

    f = File(id=f.id)
    # The file isn't for a post in room 1, so shouldn't have been associated:
    assert f.post_id is None
    assert f.expiry == from_now.hours(1)

    # Disallow setting the room image to some foreign room's upload
    r = sogs_put(client, f'/room/{room.token}', {'image': f.id}, global_admin)
    assert r.status_code == 406


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
    with pytest.raises(wexc.Forbidden):
        sogs_delete(client, f'/room/{room.token}/message/{id}', user2)


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


def _file_upload(client, room, user, *, unsafe=False, utf=False, filename):

    url_post = f"/room/{room.token}/file"
    file_content = random(1024)
    filename_escaped = urllib.parse.quote(filename.encode('utf-8'))
    r = sogs_post_raw(
        client,
        url_post,
        file_content,
        user,
        extra_headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_escaped}"},
    )
    assert r.status_code == 201
    assert 'id' in r.json
    id = r.json.get('id')
    assert id is not None
    assert id != 0
    r = sogs_get(client, f'/room/{room.token}/file/{id}', user)
    assert r.status_code == 200
    assert r.data == file_content
    expected = ('attachment', {'filename': filename.replace('\0', '\ufffd').replace('/', '\ufffd')})
    assert parse_options_header(r.headers.get('content-disposition')) == expected
    f = File(id=id)
    if unsafe or utf:
        exp_path = f'{id}_' + re.sub(sogs.config.UPLOAD_FILENAME_BAD, "_", filename)
    else:
        exp_path = f'{id}_{filename}'
    assert path.split(f.path)[-1] == exp_path


def test_file_upload(client, room, user):
    _file_upload(client, room, user, filename='normal.txt')


def test_file_upload_fuzz(client, room, user):
    rng = Random(42)
    for _ in range(500):
        filename = bytes(rng.getrandbits(8) for _ in range(32)).decode('latin1')
        _file_upload(client, room, user, filename=filename, unsafe=True)


def test_file_upload_backslashes(client, room, user):
    # When the filename *begins* with 1 or more backslashes then for some reason they all get
    # doubled up by the test client, but later backslashes don't.  We switched to produce the
    # UTF-8 encoded filename header ourself; this test is to make sure this doesn't reoccur.
    _file_upload(client, room, user, filename='\\abc', unsafe=True)
    _file_upload(client, room, user, filename='\\\\abc', unsafe=True)


def test_file_upload_unsafe(client, room, user):
    _file_upload(client, room, user, filename='ass,asss---ass../../../asd', unsafe=True)
    _file_upload(client, room, user, filename='/dev/null', unsafe=True)
    _file_upload(client, room, user, filename='/proc/self/exe', unsafe=True)
    _file_upload(client, room, user, filename='%0a%0d%%%%', unsafe=True)


def test_file_upload_emoji(client, room, user):
    _file_upload(client, room, user, filename='🎉.txt', utf=True)


def test_file_upload_emoji_extra(client, room, user):
    _file_upload(client, room, user, filename='🎉.🎉', utf=True)


def test_file_upload_emoji_unsafe(client, room, user):
    _file_upload(client, room, user, filename='🎉.🎉---../../../asd', unsafe=True, utf=True)
    _file_upload(client, room, user, filename='%00🎉.🎉---../../../asd', unsafe=True, utf=True)


def test_file_upload_banned_user(client, room, banned_user):
    url_post = f"/room/{room.token}/file"
    r = sogs_post_raw(client, url_post, random(1024), banned_user)
    assert r.status_code == 403


def test_file_not_found(client, room, user, banned_user):
    filename = 'bogus.exe'
    url_get = f'/room/{room.token}/file/99999/{filename}'
    r = sogs_get(client, url_get, user)
    assert r.status_code == 404
    r = sogs_get(client, url_get, banned_user)
    assert r.status_code == 403


def test_file_read_false(client, room, user, mod):
    filename = 'bogus.XD'
    url_post = f"/room/{room.token}/file"
    file_content = random(1024)
    r = sogs_post_raw(
        client,
        url_post,
        file_content,
        user,
        extra_headers={"Content-Disposition": ('attachment', {'filename': filename})},
    )
    assert r.status_code == 201
    assert 'id' in r.json
    id = r.json['id']
    assert id
    room.set_permissions(user, mod=mod, read=False)
    r = sogs_get(client, f'/room/{room.token}/file/{id}/{filename}', user)
    assert r.status_code == 403


def test_file_write_false(client, room, user, mod):
    room.set_permissions(user, mod=mod, write=False)
    filename = 'bogus.XD'
    url_post = f"/room/{room.token}/file"
    file_content = random(1024)
    r = sogs_post_raw(
        client,
        url_post,
        file_content,
        user,
        extra_headers={"Content-Disposition": ('attachment', {'filename': filename})},
    )
    assert r.status_code == 403


def test_file_upload_false(client, room, user, mod):
    room.set_permissions(user, mod=mod, upload=False)
    filename = 'bogus.XD'
    url_post = f"/room/{room.token}/file"
    file_content = random(1024)
    r = sogs_post_raw(
        client,
        url_post,
        file_content,
        user,
        extra_headers={"Content-Disposition": ('attachment', {'filename': filename})},
    )
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
    with pytest.raises(wexc.Forbidden):
        sogs_delete(client, f'/room/{room.token}/all/{user.session_id}', user2)
    assert len(room.get_messages_for(user, recent=True)) == 256
    assert room.check_unbanned(user) and room.check_unbanned(user2)


def test_remove_all_posts_from_room_not_allowed_for_user(client, room, mod, user, no_rate_limit):
    for _ in range(256):
        _make_dummy_post(room, mod)
    with pytest.raises(wexc.Forbidden):
        sogs_delete(client, f'/room/{room.token}/all/{mod.session_id}', user)
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
