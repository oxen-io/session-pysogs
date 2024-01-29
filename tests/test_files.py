from request import sogs_get, sogs_post, sogs_put, sogs_post_raw, sogs_delete
from util import config_override, from_now, pad64
from sogs.model.file import File
import sogs.model.exc
from sogs import utils
import sogs.config
import urllib
from werkzeug.http import parse_options_header
from os import path
from nacl.utils import random
from random import Random
import pytest
import re


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


def _file_upload(client, room, user, *, unsafe=False, utf=False, filename):
    url_post = f"/room/{room.token}/file"
    file_content = random(1024)
    filename = filename.replace('\0', '\ufffd').replace('/', '\ufffd')
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

    # FIXME: the filename.replace \0 and / above was in this "expected" line, but this caused
    #        the following assertion to fail.  What is the correct behavior?
    expected = ('attachment', {'filename': filename})
    content_disposition = parse_options_header(r.headers.get('content-disposition'))
    assert content_disposition == expected
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


def test_file_unexpiring(client, room, user):
    with config_override(UPLOAD_DEFAULT_EXPIRY=None):
        filedata, headers = _make_file_upload('up1.txt')
        r = sogs_post_raw(client, f'/room/{room.token}/file', filedata, user, extra_headers=headers)
        assert r.status_code == 201
        assert 'id' in r.json
        f = File(id=r.json.get('id'))
        # - verify that the file expiry is 1h from now (±1s)
        assert f.expiry == from_now.hours(1)
        # - add a post that references the file
        d, s = (utils.encode_base64(x) for x in (b"post data", pad64("sig")))
        post_info = {'data': d, 'signature': s, 'files': [f.id]}
        r = sogs_post(client, f'/room/{room.token}/message', post_info, user)
        assert r.status_code == 201
        assert 'id' in r.json
        post_id = r.json.get('id')
        f = File(id=f.id)
        assert f.post_id == post_id
        assert f.expiry is None
