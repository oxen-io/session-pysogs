import pytest
import time
from sogs.model.room import Room
from sogs.model.file import File
from sogs import utils
import sogs.config
from auth import x_sogs_for


def test_list(client, room, user, user2, admin, mod, global_mod, global_admin):

    room2 = Room.create('room2', name='Room 2', description='Test suite testing room2')
    room2.default_write = False
    room2.default_upload = False

    room3 = Room.create('room3', name='Room 3', description='Test suite testing room3')
    room3.default_read = False
    room3.default_write = False
    room3.default_upload = False

    r2_expected = {
        "token": "room2",
        "name": "Room 2",
        "description": "Test suite testing room2",
        "info_updates": 0,
        "message_sequence": 0,
        "created": room2.created,
        "active_users": 0,
        "active_users_cutoff": int(86400 * sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [],
        "admins": [],
        "moderator": False,
        "admin": False,
        "read": True,
        "write": False,
        "upload": False,
    }
    r_expected = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 2,
        "message_sequence": 0,
        "created": room.created,
        "active_users": 0,
        "active_users_cutoff": int(86400 * sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [mod.session_id],
        "admins": [admin.session_id],
        "moderator": False,
        "admin": False,
        "read": True,
        "write": True,
        "upload": True,
    }
    r3_expected = {
        "token": "room3",
        "name": "Room 3",
        "description": "Test suite testing room3",
        "info_updates": 0,
        "message_sequence": 0,
        "created": room3.created,
        "active_users": 0,
        "active_users_cutoff": int(86400 * sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [],
        "admins": [],
        "moderator": False,
        "admin": False,
        "read": True,
        "write": False,
        "upload": False,
    }

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

    # Unauthed user: should see just room and room2 but not room3
    r = client.get("/rooms")
    assert r.status_code == 200
    assert r.json == [r2_expected, r_expected]

    r = client.get("/rooms", headers=x_sogs_for(user, "GET", "/rooms"))
    assert r.status_code == 200
    assert r.json == [r2_expected, r_expected]

    r = client.get("/rooms", headers=x_sogs_for(user2, "GET", "/rooms"))
    assert r.status_code == 200
    assert r.json == [{**r2_expected, "write": True}, r3_expected, r_expected]

    r = client.get("/rooms", headers=x_sogs_for(mod, "GET", "/rooms"))
    assert r.status_code == 200
    assert r.json == [r2_expected, {**r_expected, **exp_mod}]

    r = client.get("/rooms", headers=x_sogs_for(admin, "GET", "/rooms"))
    assert r.status_code == 200
    assert r.json == [r2_expected, {**r_expected, **exp_admin}]

    r = client.get("/rooms", headers=x_sogs_for(global_mod, "GET", "/rooms"))
    assert r.status_code == 200
    assert r.json == [
        {**r2_expected, **exp_gmod},
        {**r3_expected, **exp_gmod},
        {**r_expected, **exp_gmod},
    ]

    r = client.get("/rooms", headers=x_sogs_for(global_admin, "GET", "/rooms"))
    assert r.status_code == 200
    assert r.json == [
        {**r2_expected, **exp_gadmin},
        {**r3_expected, **exp_gadmin},
        {**r_expected, **exp_gadmin},
    ]

    r = client.get("/room/room3", headers=x_sogs_for(user, "GET", "/room/room3"))
    assert r.status_code == 200
    assert r.json == {**r3_expected, "read": False}

    r = client.get("/room/room3", headers=x_sogs_for(user2, "GET", "/room/room3"))
    assert r.status_code == 200
    assert r.json == r3_expected

    r = client.get("/room/room3", headers=x_sogs_for(global_admin, "GET", "/room/room3"))
    assert r.status_code == 200
    assert r.json == {**r3_expected, **exp_gadmin}


def test_polling(client, room, user, user2, mod, admin, global_mod, global_admin):
    r = client.get("/room/test-room", headers=x_sogs_for(user, "GET", "/room/test-room"))
    assert r.status_code == 200
    info_up = r.json['info_updates']
    assert info_up == 2

    basic = {
        'token': 'test-room',
        'active_users': 1,
        'moderator': False,
        'admin': False,
        'read': True,
        'write': True,
        'upload': True,
    }
    details = {
        "token": "test-room",
        "name": "Test room",
        "description": "Test suite testing room",
        "info_updates": 2,
        "message_sequence": 0,
        "created": room.created,
        "active_users": 1,
        "active_users_cutoff": int(86400 * sogs.config.ROOM_DEFAULT_ACTIVE_THRESHOLD),
        "moderators": [mod.session_id],
        "admins": [admin.session_id],
        "moderator": False,
        "admin": False,
        "read": True,
        "write": True,
        "upload": True,
    }

    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    assert r.json == basic

    # Make various changes that should each update the room info updates:

    # Changing name
    room.name = 'Test Room'
    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    details['info_updates'] += 1
    details['name'] = 'Test Room'
    assert r.json == {**basic, 'details': details}

    info_up += 1
    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(mod, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    basic['active_users'] += 1
    details['active_users'] += 1
    assert r.status_code == 200
    assert r.json == {**basic, 'moderator': True}

    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(admin, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    basic['active_users'] += 1
    details['active_users'] += 1
    assert r.json == {**basic, 'moderator': True, 'admin': True}

    # Changing description
    room.description = 'Test suite testing room new desc'
    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    details['info_updates'] += 1
    details['description'] = 'Test suite testing room new desc'
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']
    assert (
        'details'
        not in client.get(
            f"/room/test-room/pollInfo/{info_up}",
            headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
        ).json
    )

    # Setting room image
    img = File(
        id=room.upload_file(
            content=b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02'
            b'\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDAT\x08\xd7c\x90\x8dp\x04\x00\x01L\x00\xb7\xb1'
            b'o\xa7\\\x00\x00\x00\x00IEND\xaeB`\x82',
            uploader=mod,
            filename='tiny.png',
        )
    )
    room.image = img

    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    details['image_id'] = 1
    details['info_updates'] += 1
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    assert (
        'details'
        not in client.get(
            f"/room/test-room/pollInfo/{info_up}",
            headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
        ).json
    )

    # Add moderator
    room.set_moderator(user, added_by=admin)

    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    details['info_updates'] += 1
    details['moderators'] = sorted(details['moderators'] + [user.session_id])
    assert r.json == {
        **basic,
        'moderator': True,
        'details': {
            **details,
            'moderator': True,
            'hidden_admins': [global_admin.session_id],
            'hidden_moderators': [global_mod.session_id],
        },
    }
    info_up += 1
    assert info_up == details['info_updates']

    # Remove moderator
    room.remove_moderator(user, removed_by=admin)
    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    details['info_updates'] += 1
    details['moderators'] = sorted(x for x in details['moderators'] if x != user.session_id)
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    # Add global admin
    user2.set_moderator(added_by=global_admin, admin=True, visible=True)

    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    details['info_updates'] += 1
    details['admins'] = sorted(details['admins'] + [user2.session_id])
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    # Remove global admin
    user2.remove_moderator(removed_by=user2)
    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    details['info_updates'] += 1
    details['admins'] = sorted(x for x in details['admins'] if x != user2.session_id)
    assert r.json == {**basic, 'details': details}
    info_up += 1
    assert info_up == details['info_updates']

    # Post a message should *not* change info_updates, but should change the message_sequence
    room.add_post(user, b'fake data', b'fake sig')

    r = client.get(
        f"/room/test-room/pollInfo/{info_up}",
        headers=x_sogs_for(user, "GET", f"/room/test-room/pollInfo/{info_up}"),
    )
    assert r.status_code == 200
    assert 'details' not in r.json

    details['message_sequence'] += 1
    r = client.get("/room/test-room", headers=x_sogs_for(user, "GET", "/room/test-room"))
    assert r.json['message_sequence'] == details['message_sequence']


def test_fetch_since(client, room, user, no_rate_limit):
    top_fetched = 0
    fetches = 0
    counter = 0  # seqno should follow this
    counts = (1, 1, 1, 2, 0, 3, 0, 0, 5, 7, 11, 12, 0, 25, 0, 101, 0, 203, 0, 100, 200)
    for n in counts:
        for i in range(counter + 1, counter + 1 + n):
            room.add_post(user, f"fake data {i}".encode(), f"fake sig {i}".encode())
        counter += n

        done = False
        while not done:
            url = f"/room/test-room/messages/since/{top_fetched}"
            r = client.get(url, headers=x_sogs_for(user, "GET", url))
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
                assert utils.decode_base64(post['signature']) == f"fake sig {j}".encode()
                assert -1 <= post['posted'] - time.time() <= 1

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
        r = client.get(url, headers=x_sogs_for(user, "GET", url))
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
        room.add_post(user, f"data-{i}".encode(), f"fake sig {i}".encode())

    url = "/room/test-room/messages/recent"
    r100 = client.get(url, headers=x_sogs_for(user, "GET", url))
    assert len(r100.json) == 100

    assert [p['id'] for p in r100.json] == list(range(1000, 900, -1))

    url = "/room/test-room/messages/recent?limit=201"
    r201 = client.get(url, headers=x_sogs_for(user, "GET", url))
    assert len(r201.json) == 201

    assert r100.json == r201.json[:100]

    url = f"/room/test-room/messages/before/{r100.json[-1]['id']}?limit=101"
    r101 = client.get(url, headers=x_sogs_for(user, "GET", url))
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
        r = client.get(url, headers=x_sogs_for(user, "GET", url))
        assert r.status_code == 200
        assert len(r.json) == limit
        assert r.json[0]['id'] == next_exp
        assert r.json[-1]['id'] == next_exp - limit + 1
        next_exp -= limit
        before = r.json[-1]['id']

    assert next_exp == 0
    assert before == 1
    url = f"/room/test-room/messages/before/{before}"
    r = client.get(url, headers=x_sogs_for(user, "GET", url))
    assert len(r.json) == 0


def test_fetch_one(client, room, user, no_rate_limit):
    posts = [room.add_post(user, f"data-{i}".encode(), f"fake sig {i}".encode()) for i in range(10)]

    for i in (5, 2, 8, 7, 9, 6, 10, 1, 3, 4):
        url = f"/room/test-room/message/{i}"
        r = client.get(url, headers=x_sogs_for(user, "GET", url))
        assert r.status_code == 200
        p = posts[i - 1].copy()
        for x in ('data', 'signature'):
            p[x] = utils.encode_base64(p[x])
        assert r.json == p


def test_pinning(client, room, user, admin, no_rate_limit):
    for i in range(10):
        room.add_post(user, f"data-{i}".encode(), f"fake sig {i}".encode())

    def room_json():
        r = client.get("/room/test-room", headers=x_sogs_for(user, "GET", "/room/test-room"))
        assert r.status_code == 200
        return r.json

    assert room_json()['info_updates'] == 1

    import werkzeug.exceptions

    url = "/room/test-room/pin/3"
    with pytest.raises(werkzeug.exceptions.Forbidden):
        r = client.post(url, data=b'{}', headers=x_sogs_for(user, "POST", url, b'{}'))

    assert room_json()['info_updates'] == 1

    r = client.post(url, data=b'{}', headers=x_sogs_for(admin, "POST", url, b'{}'))
    assert r.status_code == 200

    ri = room_json()
    assert ri['info_updates'] == 2
    assert -1 < ri['pinned_messages'][0]['pinned_at'] - time.time() < 1
    del ri['pinned_messages'][0]['pinned_at']
    assert ri['pinned_messages'] == [{'id': 3, 'pinned_by': admin.session_id}]

    url = "/room/test-room/pin/7"
    r = client.post(url, data=b'{}', headers=x_sogs_for(admin, "POST", url, b'{}'))
    assert r.status_code == 200
    time.sleep(0.001)
    url = "/room/test-room/pin/5"
    r = client.post(url, data=b'{}', headers=x_sogs_for(admin, "POST", url, b'{}'))
    assert r.status_code == 200

    ri = room_json()
    assert ri['info_updates'] == 4
    rpm = ri['pinned_messages']
    assert (
        time.time() - 1
        < rpm[0]['pinned_at']
        < rpm[1]['pinned_at']
        < rpm[2]['pinned_at']
        < time.time() + 1
    )
    for p in ri['pinned_messages']:
        del p['pinned_at']

    assert ri['pinned_messages'] == [
        {'id': 3, 'pinned_by': admin.session_id},
        {'id': 7, 'pinned_by': admin.session_id},
        {'id': 5, 'pinned_by': admin.session_id},
    ]

    url = "/room/test-room/pin/7"
    r = client.post(url, data=b'{}', headers=x_sogs_for(admin, "POST", url, b'{}'))
    assert r.status_code == 200

    ri = room_json()
    assert ri['info_updates'] == 5
    rpm = ri['pinned_messages']
    assert (
        time.time() - 1
        < rpm[0]['pinned_at']
        < rpm[1]['pinned_at']
        < rpm[2]['pinned_at']
        < time.time() + 1
    )
    for p in ri['pinned_messages']:
        del p['pinned_at']

    assert ri['pinned_messages'] == [
        {'id': 3, 'pinned_by': admin.session_id},
        {'id': 5, 'pinned_by': admin.session_id},
        {'id': 7, 'pinned_by': admin.session_id},
    ]

    url = "/room/test-room/unpin/5"
    r = client.post(url, data=b'{}', headers=x_sogs_for(admin, "POST", url, b'{}'))
    assert r.status_code == 200

    ri = room_json()
    rpm = ri['pinned_messages']
    assert time.time() - 1 < rpm[0]['pinned_at'] < rpm[1]['pinned_at'] < time.time() + 1
    for p in ri['pinned_messages']:
        del p['pinned_at']

    assert ri['pinned_messages'] == [
        {'id': 3, 'pinned_by': admin.session_id},
        {'id': 7, 'pinned_by': admin.session_id},
    ]

    url = "/room/test-room/unpin/all"
    r = client.post(url, data=b'{}', headers=x_sogs_for(admin, "POST", url, b'{}'))
    assert r.status_code == 200

    assert 'pinned_messages' not in room_json()
