import time
from util import pad64
from request import sogs_get, sogs_put, sogs_delete


def test_reactions(client, room, room2, user, user2, mod, admin, global_mod, global_admin):
    for i in range(1, 11):
        poster = admin if i == 6 else mod if i in (4, 7) else user2 if i % 2 == 0 else user
        rm = room2 if i == 5 else room
        rm.add_post(poster, f"fake data {i}".encode(), pad64(f"fake sig {i}"))

    r = sogs_get(client, "/room/test-room/messages/since/0?t=r", user)
    assert r.status_code == 200
    assert isinstance(r.json, list)
    assert len(r.json) == 9
    assert [x['id'] for x in r.json] == [1, 2, 3, 4, 6, 7, 8, 9, 10]
    assert [x.get('reactions') for x in r.json] == [{}] * 9

    seqno = r.json[-1]["seqno"]

    new_seqno = seqno
    for x in ("🖕", "🍆", "f", "y/n", "abcdefghijkl"):
        r = sogs_put(client, f"/room/test-room/reaction/4/{x}", {}, user)
        assert r.status_code == 200
        new_seqno += 1
        assert r.json == {"added": True, "seqno": new_seqno}

    # Without the ?t=r flag, we don't get reaction-only updates:
    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}", user2)
    assert r.status_code == 200
    assert r.json == []

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r", user2)
    assert [x['id'] for x in r.json] == [4]
    assert r.json[0].keys() == {'id', 'reactions', 'seqno'}
    assert r.json[0]['seqno'] == seqno + 5
    seqno += 5

    # Already present:
    r = sogs_put(client, "/room/test-room/reaction/4/🖕", {}, user)
    assert r.status_code == 200
    assert r.json == {"added": False, "seqno": seqno}
    assert sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r", user2).json == []

    r = sogs_get(client, "/room/test-room/messages/since/0?t=r", user2)
    assert [x['id'] for x in r.json] == [1, 2, 3, 6, 7, 8, 9, 10, 4]

    assert r.json[-1]["seqno"] == seqno

    r = sogs_put(client, "/room/test-room/reaction/10/🍍", {}, user)
    assert r.json == {"added": True, "seqno": seqno + 1}
    r = sogs_put(client, "/room/test-room/reaction/4/🖕", {}, user2)
    assert r.json == {"added": True, "seqno": seqno + 2}
    r = sogs_put(client, "/room/test-room/reaction/4/🍍", {}, user)
    assert r.json == {"added": True, "seqno": seqno + 3}

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r", user2)
    assert {x['id']: x['seqno'] for x in r.json} == {4: seqno + 3, 10: seqno + 1}
    seqno_10 = seqno + 1
    seqno += 3

    r = sogs_get(client, "/room/room2/messages/since/0?t=r", user2)
    assert {x['id']: x['seqno'] for x in r.json} == {5: 1}

    # If there is both an edit and new reactions, we should get the full message including reactions
    # and *not* a separate reactions row.
    room.edit_post(mod, 4, data=b'edited fake data 4', sig=pad64(b'fake sig 4b'))
    new_seqno = seqno + 1
    for u in (user2, global_admin, mod, global_mod, admin):
        r = sogs_put(client, "/room/test-room/reaction/4/🍍", {}, u)
        new_seqno += 1
        assert r.json == {'added': True, 'seqno': new_seqno}
    assert sogs_put(client, "/room/test-room/reaction/4/🍍", {}, user).json == {
        'added': False,
        "seqno": new_seqno,
    }
    r = sogs_put(client, "/room/test-room/reaction/4/🦒🦍🐍🐊🦢🦁🦎", {}, user)
    assert r.json == {'added': True, "seqno": new_seqno + 1}

    # user2 is the fourth reactor (of 5) and so should get ourself last in the truncated reactor
    # list:
    for u in (user, mod, global_mod, user2, admin):
        r = sogs_put(client, "/room/test-room/reaction/4/🂤", {}, u)

    # user2 is fifth (of 5) and so should not be in the truncated reactor list (but should still get
    # "you"):
    for u in (user, mod, global_mod, global_admin, user2):
        r = sogs_put(client, "/room/test-room/reaction/4/🂵", {}, u)

    exp_reactions = {
        'abcdefghijkl': {'index': 4, 'count': 1, 'reactors': [user.session_id]},
        'f': {'index': 2, 'count': 1, 'reactors': [user.session_id]},
        'y/n': {'index': 3, 'count': 1, 'reactors': [user.session_id]},
        '🍆': {'index': 1, 'count': 1, 'reactors': [user.session_id]},
        '🍍': {
            'index': 5,
            'count': 6,
            'reactors': [u.session_id for u in (user, user2, global_admin, mod)],
            'you': True,
        },
        '🖕': {
            'index': 0,
            'count': 2,
            'reactors': [user.session_id, user2.session_id],
            'you': True,
        },
        '🦒🦍🐍🐊🦢🦁🦎': {'index': 6, 'count': 1, 'reactors': [user.session_id]},
        '🂤': {
            'index': 7,
            'count': 5,
            'reactors': [u.session_id for u in (user, mod, global_mod, user2)],
            'you': True,
        },
        '🂵': {
            'index': 8,
            'count': 5,
            'reactors': [u.session_id for u in (user, mod, global_mod, global_admin)],
            'you': True,
        },
    }

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r", user2).json
    assert len(r) == 1
    for x in ('edited', 'posted'):
        del r[0][x]
    assert r == [
        {
            'id': 4,
            'data': 'ZWRpdGVkIGZha2UgZGF0YSA0',
            'signature': 'ZmFrZSBzaWcgNGI' + 'A' * 71 + '==',
            'seqno': seqno + 17,
            'session_id': mod.using_id,
            'reactions': exp_reactions,
        }
    ]

    # If we fetch just after the edit, we should only get the reactions:

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno+1}?t=r", user2)
    assert r.json == [{'id': 4, 'seqno': seqno + 17, 'reactions': exp_reactions}]

    seqno += 17

    # Fetch the *full* list of reactors
    r = sogs_get(client, "/room/test-room/reactors/4/🍍", user).json
    # Returns pairs where second value is the time; make sure time is ordered and recent, then kill
    # it
    last_time = time.time() - 3.0
    assert len(r) == 6
    for x in r:
        assert x[1] > last_time
        last_time = x[1]
        x[1] = 0

    assert r == [[u.session_id, 0] for u in (user, user2, global_admin, mod, global_mod, admin)]

    # Partial list
    r = sogs_get(client, "/room/test-room/reactors/4/🍍?reactors=5", user).json
    r = [x[0] for x in r]
    assert r == [u.session_id for u in (user, user2, global_admin, mod, global_mod, admin)]

    r = sogs_delete(client, "/room/test-room/reaction/4/🍍", user)
    del exp_reactions['🍍']['reactors'][0]
    exp_reactions['🍍']['count'] -= 1

    # We're reducing the reactor limit below, so chop off the last reactor from these in the
    # expected result:
    for card in '🂤🂵':
        del exp_reactions[card]['reactors'][-1]

    # Also tests that the `reactors` query param is working right
    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=3", user2)
    assert r.json == [{'id': 4, 'seqno': seqno + 1, 'reactions': exp_reactions}]

    # reactors=0 means skip the reactors entirely
    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=0", user2)
    for v in exp_reactions.values():
        del v['reactors']
    assert r.json == [{'id': 4, 'seqno': seqno + 1, 'reactions': exp_reactions}]
    seqno += 1

    # Non-mod shouldn't be able to delete all:
    r = sogs_delete(client, "/room/test-room/reactions/4", user2)
    assert r.status_code == 403
    r = sogs_delete(client, "/room/test-room/reactions/4/🍍", user2)
    assert r.status_code == 403

    r = sogs_delete(client, "/room/test-room/reactions/4/🍍", global_admin)
    assert r.status_code == 200
    assert exp_reactions["🍍"]["count"] == 5
    assert r.json == {"removed": 5, "seqno": seqno + 5}
    del exp_reactions["🍍"]
    for reaction in ("🦒🦍🐍🐊🦢🦁🦎", '🂤', '🂵'):
        exp_reactions[reaction]["index"] -= 1

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=0", user2)
    assert r.json == [{'id': 4, 'seqno': seqno + 5, 'reactions': exp_reactions}]
    seqno += 5

    n_other = sum(x["count"] for x in exp_reactions.values())
    r = sogs_delete(client, "/room/test-room/reactions/4", mod)
    assert r.status_code == 200
    assert r.json == {"removed": n_other, "seqno": seqno + n_other}

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=0", user2)
    assert r.json == [{'id': 4, 'reactions': {}, 'seqno': seqno + n_other}]
    seqno += n_other

    # Other posts shouldn't have been affected
    r = sogs_get(client, "/room/test-room/messages/since/0?t=r&reactors=0", user2).json
    assert [x['id'] for x in r] == [1, 2, 3, 6, 7, 8, 9, 10, 4]
    assert [x['id'] for x in r if x['reactions']] == [10]
    assert r[7]['reactions'] == {'🍍': {'count': 1, 'index': 0}}

    assert sogs_delete(client, "/room/test-room/reaction/10/🍍", global_mod).json == {
        'removed': False,
        'seqno': seqno_10,
    }
    assert sogs_delete(client, "/room/test-room/reaction/10/🍍", user).json == {
        'removed': True,
        'seqno': seqno + 1,
    }

    assert sogs_put(client, "/room/test-room/reaction/9/🍍", {}, user).json == {
        'added': True,
        "seqno": seqno + 2,
    }
    assert sogs_put(client, "/room/test-room/reaction/9/🍍", {}, user2).json == {
        'added': True,
        "seqno": seqno + 3,
    }
    r = sogs_get(client, "/room/test-room/message/9", mod).json
    assert 'reactions' in r
    assert r.get('reactions') == {
        '🍍': {"count": 2, "index": 0, "reactors": [user.session_id, user2.session_id]}
    }

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=0", user2).json

    assert len(r) == 2
    assert r[0]['id'] == 10
    assert not r[0]['reactions']  # We removed the last 🍍 reaction above
    # seqno went up because we removed one and added two reactions:
    seqno += 3
    assert r[1] == {
        'id': 9,
        'seqno': seqno,
        'reactions': {'🍍': {'index': 0, 'count': 2, 'you': True}},
    }

    assert sogs_delete(client, "/room/test-room/message/9", admin).status_code == 200
    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r", user2).json
    # We should get the deletion, and it should have no reactions:
    assert len(r) == 1
    r = r[0]
    # seqno goes up by three because of the deletion itself *and* the implied deletion of the two
    # reactions on the message.
    seqno += 3
    del r['posted']
    del r['edited']
    assert r == {
        'id': 9,
        'data': None,
        'deleted': True,
        'seqno': seqno,
        'session_id': user.using_id,
    }


def test_reaction_encoding(client, room, user, user2):
    room.add_post(user, b"fake data", pad64("fake sig"))

    r = sogs_put(client, "/room/test-room/reaction/1/🍍", {}, user)
    assert r.status_code == 200
    r.json == {}

    r = sogs_put(client, "/room/test-room/reaction/1/%F0%9F%8D%8D", {}, user2)
    assert r.status_code == 200
    r.json == {}

    r = sogs_put(client, "/room/test-room/reaction/1/❤️", {}, user2)
    assert r.status_code == 200
    r.json == {}

    r = sogs_put(client, "/room/test-room/reaction/1/%E2%9D%A4%EF%B8%8F", {}, user)
    assert r.status_code == 200
    r.json == {}

    r = sogs_get(client, "/room/test-room/messages/since/0?t=r&reactors=0", user)
    assert r.status_code == 200
    r = r.json
    assert len(r) == 1
    del r[0]['posted']
    assert r == [
        {
            'data': 'ZmFrZSBkYXRh',  # fake data
            'id': 1,
            'seqno': 5,
            'session_id': user.using_id,
            'signature': 'ZmFrZSBzaWc' + 'A' * 75 + '==',
            'reactions': {
                '❤️': {'count': 2, 'index': 1, 'you': True},
                '🍍': {'count': 2, 'index': 0, 'you': True},
            },
        }
    ]


def test_reaction_ordering(client, room, user, user2):
    for i in (1, 2):
        room.add_post(user, f"fake data {i}".encode(), pad64(f"fake sig {i}"))
    seqno = 2

    for x in ("🖕", "f", "🍆", "y/n", "abcdefghijkl", "🍍"):
        r = sogs_put(client, f"/room/test-room/reaction/1/{x}", {}, user)
        assert r.status_code == 200
        seqno += 1
        assert r.json == {"added": True, "seqno": seqno}

    for x in ("‽", "abcdefghijkl", "f", "🍍", "🖕"):
        r = sogs_put(client, f"/room/test-room/reaction/2/{x}", {}, user2)
        assert r.status_code == 200
        seqno += 1
        assert r.json == {"added": True, "seqno": seqno}

    for x in ("🖕", "f", "🍆", "y/n", "abcdefghijkl", "🍍", "🫑"):
        r = sogs_put(client, f"/room/test-room/reaction/2/{x}", {}, user)
        assert r.status_code == 200
        seqno += 1
        assert r.json == {"added": True, "seqno": seqno}
    seqno_2 = seqno

    for x in ("abcdefghijkl", "f", "🍍", "🖕", "🎂"):
        r = sogs_put(client, f"/room/test-room/reaction/1/{x}", {}, user2)
        assert r.status_code == 200
        seqno += 1
        assert r.json == {"added": True, "seqno": seqno}

    u1 = [user.session_id]
    u2 = [user2.session_id]
    u1u2 = u1 + u2
    u2u1 = u2 + u1
    exp_reacts_1 = {
        "🖕": {'index': 0, 'count': 2, 'reactors': u1u2, 'you': True},
        "f": {'index': 1, 'count': 2, 'reactors': u1u2, 'you': True},
        "🍆": {'index': 2, 'count': 1, 'reactors': u1},
        "y/n": {'index': 3, 'count': 1, 'reactors': u1},
        "abcdefghijkl": {'index': 4, 'count': 2, 'reactors': u1u2, 'you': True},
        "🍍": {'index': 5, 'count': 2, 'reactors': u1u2, 'you': True},
        "🎂": {'index': 6, 'count': 1, 'reactors': u2, 'you': True},
    }
    exp_reacts_2 = {
        "‽": {'index': 0, 'count': 1, 'reactors': u2, 'you': True},
        "abcdefghijkl": {'index': 1, 'count': 2, 'reactors': u2u1, 'you': True},
        "f": {'index': 2, 'count': 2, 'reactors': u2u1, 'you': True},
        "🍍": {'index': 3, 'count': 2, 'reactors': u2u1, 'you': True},
        "🖕": {'index': 4, 'count': 2, 'reactors': u2u1, 'you': True},
        "🍆": {'index': 5, 'count': 1, 'reactors': u1},
        "y/n": {'index': 6, 'count': 1, 'reactors': u1},
        "🫑": {'index': 7, 'count': 1, 'reactors': u1},
    }

    r = sogs_get(client, "/room/test-room/messages/since/2?t=r", user2)
    assert r.json == [
        {'id': 2, 'reactions': exp_reacts_2, 'seqno': seqno_2},
        {'id': 1, 'reactions': exp_reacts_1, 'seqno': seqno},
    ]

    # Deleting a user reaction while the post has other user reactions should not affect the order:
    assert sogs_delete(client, "/room/test-room/reaction/1/f", user).json == {
        'removed': True,
        'seqno': seqno + 1,
    }
    seqno += 1
    exp_reacts_1["f"]["count"] -= 1
    exp_reacts_1["f"]["reactors"] = u2

    r = sogs_get(client, "/room/test-room/messages/since/2?t=r", user2)
    assert r.json == [
        {'id': 2, 'reactions': exp_reacts_2, 'seqno': seqno_2},
        {'id': 1, 'reactions': exp_reacts_1, 'seqno': seqno},
    ]

    # Deleting the last reaction and then adding it again should put it back at the *end*, not in
    # its original position:
    assert sogs_delete(client, "/room/test-room/reaction/1/f", user2).json == {
        'removed': True,
        'seqno': seqno + 1,
    }
    assert sogs_put(client, "/room/test-room/reaction/1/f", {}, user2).json == {
        'added': True,
        'seqno': seqno + 2,
    }
    seqno += 2

    for v in exp_reacts_1.values():
        if v["index"] > exp_reacts_1["f"]["index"]:
            v["index"] -= 1
    exp_reacts_1["f"]["index"] = len(exp_reacts_1) - 1
    r = sogs_get(client, "/room/test-room/messages/since/2?t=r", user2)
    assert r.json == [
        {'id': 2, 'reactions': exp_reacts_2, 'seqno': seqno_2},
        {'id': 1, 'reactions': exp_reacts_1, 'seqno': seqno},
    ]
