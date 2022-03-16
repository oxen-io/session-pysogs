from nacl.utils import random
from request import sogs_post, sogs_post_raw
from util import config_override, from_now, pad64
from sogs.model.file import File
from sogs import utils


def _make_file_upload(filename):
    return random(1024), {"Content-Disposition": ('attachment', {'filename': filename})}


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
