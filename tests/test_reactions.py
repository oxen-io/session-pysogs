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
    assert [x.get('reactions') for x in r.json] == [None] * 9

    seqno = r.json[-1]["seqno"]

    for x in ("🖕", "🍆", "f", "y/n", "abcdefghijkl"):
        r = sogs_put(client, f"/room/test-room/reaction/4/{x}", {}, user)
        assert r.status_code == 200
        assert r.json["added"]

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
    assert not r.json["added"]
    assert sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r", user2).json == []

    r = sogs_get(client, "/room/test-room/messages/since/0?t=r", user2)
    assert [x['id'] for x in r.json] == [1, 2, 3, 6, 7, 8, 9, 10, 4]

    assert r.json[-1]["seqno"] == seqno

    r = sogs_put(client, "/room/test-room/reaction/10/🍍", {}, user)
    assert r.json["added"]
    r = sogs_put(client, "/room/test-room/reaction/4/🖕", {}, user2)
    assert r.json["added"]
    r = sogs_put(client, "/room/test-room/reaction/4/🍍", {}, user)
    assert r.json["added"]

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r", user2)
    assert {x['id']: x['seqno'] for x in r.json} == {4: seqno + 3, 10: seqno + 1}
    seqno += 3

    r = sogs_get(client, "/room/room2/messages/since/0?t=r", user2)
    assert {x['id']: x['seqno'] for x in r.json} == {5: 1}

    # If there is both an edit and new reactions, we should get the full message including reactions
    # and *not* a separate reactions row.
    room.edit_post(mod, 4, data=b'edited fake data 4', sig=pad64(b'fake sig 4b'))
    for u in (user2, global_admin, mod, global_mod, admin):
        r = sogs_put(client, "/room/test-room/reaction/4/🍍", {}, u)
        assert r.json['added']
    assert not sogs_put(client, "/room/test-room/reaction/4/🍍", {}, user).json['added']
    r = sogs_put(client, "/room/test-room/reaction/4/🦒🦍🐍🐊🦢🦁🦎", {}, user)
    assert r.json['added']

    exp_reactions = {
        'abcdefghijkl': {'count': 1, 'reactors': [user.session_id]},
        'f': {'count': 1, 'reactors': [user.session_id]},
        'y/n': {'count': 1, 'reactors': [user.session_id]},
        '🍆': {'count': 1, 'reactors': [user.session_id]},
        '🍍': {
            'count': 6,
            'reactors': [u.session_id for u in (user, user2, global_admin, mod)],
            'you': True,
        },
        '🖕': {'count': 2, 'reactors': [user.session_id, user2.session_id], 'you': True},
        '🦒🦍🐍🐊🦢🦁🦎': {'count': 1, 'reactors': [user.session_id]},
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
            'seqno': seqno + 7,
            'session_id': mod.session_id,
            'reactions': exp_reactions,
        }
    ]

    # If we fetch just after the edit, we should only get the reactions:

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno+1}?t=r", user2)
    assert r.json == [{'id': 4, 'seqno': seqno + 7, 'reactions': exp_reactions}]

    seqno += 7

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
    n_pineapples = exp_reactions["🍍"]["count"]
    assert r.json["removed"] == n_pineapples
    del exp_reactions["🍍"]

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=0", user2)
    assert r.json == [{'id': 4, 'seqno': seqno + 5, 'reactions': exp_reactions}]
    seqno += 5

    n_other = sum(x["count"] for x in exp_reactions.values())
    r = sogs_delete(client, "/room/test-room/reactions/4", mod)
    assert r.status_code == 200
    assert r.json["removed"] == n_other

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=0", user2)
    assert r.json == [{'id': 4, 'seqno': seqno + n_other}]
    seqno += n_other

    # Other posts shouldn't have been affected
    r = sogs_get(client, "/room/test-room/messages/since/0?t=r&reactors=0", user2).json
    assert [x['id'] for x in r] == [1, 2, 3, 6, 7, 8, 9, 10, 4]
    assert [x['id'] for x in r if 'reactions' in x] == [10]
    assert r[7]['reactions'] == {'🍍': {'count': 1}}

    assert not sogs_delete(client, "/room/test-room/reaction/10/🍍", global_mod).json['removed']
    assert sogs_delete(client, "/room/test-room/reaction/10/🍍", user).json['removed']

    assert sogs_put(client, "/room/test-room/reaction/9/🍍", {}, user).json['added']
    assert sogs_put(client, "/room/test-room/reaction/9/🍍", {}, user2).json['added']
    r = sogs_get(client, "/room/test-room/message/9", mod).json
    assert 'reactions' in r
    assert r.get('reactions') == {
        '🍍': {"count": 2, "reactors": [user.session_id, user2.session_id]}
    }

    r = sogs_get(client, f"/room/test-room/messages/since/{seqno}?t=r&reactors=0", user2).json

    assert len(r) == 2
    assert r[0]['id'] == 10
    assert 'reactions' not in r[0]  # We removed the last 🍍 reaction above
    # seqno went up because we removed one and added two reactions:
    seqno += 3
    assert r[1] == {'id': 9, 'seqno': seqno, 'reactions': {'🍍': {'count': 2, 'you': True}}}

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
    assert r == {'id': 9, 'data': None, 'seqno': seqno, 'session_id': user.session_id}
