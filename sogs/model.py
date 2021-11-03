from . import db
from . import utils

b64encode = utils.encode_base64


import os
import time


def get_rooms():
    """get a list of rooms with their full info filled out"""
    with db.conn as conn:
        result = conn.execute("SELECT * FROM rooms ORDER BY token")
        return [{k: row[k] for k in row.keys()} for row in result]


def get_room(room_token):
    """Looks up a room by token and returns its info; returns None if the room doesn't exist"""
    with db.conn as conn:
        result = conn.execute("SELECT * FROM rooms WHERE token = ?", [room_token])
        row = result.fetchone()
        if row:
            return {k: row[k] for k in row.keys()}
        return None


def get_user(session_id):
    """get a user by their session id"""
    with db.conn as conn:
        result = conn.execute("SELECT * FROM users WHERE session_id = ?", [session_id])
        row = result.fetchone()
        if row:
            return {k: row[k] for k in row.keys()}
        return None


def touch_user(session_id):
    """
    Make sure a user exists in the database, updating the last activity timestamp if it does,
    creating the user otherwise.
    """
    db.conn.execute(
        """
        INSERT INTO users(session_id) VALUES(?)
        ON CONFLICT DO UPDATE SET last_active = ((julianday('now') - 2440587.5)*86400.0)
        """,
        [session_id],
    )


def check_permission(
    session_id, room_id, *, admin=False, moderator=False, read=False, write=False, upload=False
):
    """
    Checks whether `session_id` has the required permissions for room `room_id`, and isn't banned.
    Returns True if the user satisfies the permissions, false otherwise.

    Named arguments specify the permissions to require:
    - admin -- if true then the user must have admin access to the room
    - moderator -- if true then the user must have moderator (or admin) access to the room
    - read -- if true then the user must have read access
    - write -- if true then the user must have write access
    - upload -- if true then the user must have upload access

    You can specify multiple options as true, in which case all must be satisfied.  If you specify
    no flags as required then the check only checks whether a user is banned but otherwise requires
    no specific permission.
    """
    with db.conn as conn:
        touch_user(session_id)

        result = conn.execute(
            """
            SELECT banned, read, write, upload, moderator, admin FROM user_permissions
            WHERE room = ? AND session_id = ?
            """,
            [room_id, session_id],
        )
        row = result.fetchone()

        if row['admin']:
            return True
        if admin:
            return False
        if row['moderator']:
            return True
        if moderator:
            return False
        return (
            not row['banned']
            and (not read or row['read'])
            and (not write or row['write'])
            and (not upload or row['upload'])
        )


def add_post_to_room(user_id, room_id, data, sig, rate_limit_size=5, rate_limit_interval=16.0):
    """insert a post into a room from a user given room id and user id
    trims off padding and stores as needed
    """
    with db.conn as conn:
        since_limit = time.time() - rate_limit_interval
        result = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE room = ? AND user = ? AND posted >= ?",
            [room_id, user_id, since_limit],
        )
        row = result.fetchone()
        if row[0] >= rate_limit_size:
            # rate limit hit
            return
        result = conn.execute(
            "INSERT INTO messages(room, user, data, data_size, signature) VALUES(?, ?, ?, ?, ?)",
            [room_id, user_id, data.rstrip(b'\x00'), len(data), sig],
        )
        lastid = result.lastrowid
        result = conn.execute("SELECT posted, id FROM messages WHERE id = ?", [lastid])
        row = result.fetchone()
        msg = {'timestamp': utils.convert_time(row['posted']), 'server_id': row['id']}
        return msg


def get_room_image_json_blob(room_id):
    """return a json object with base64'd file contents for the image of a room"""
    filename = None
    with db.conn as conn:
        # todo: this query sucks
        result = conn.execute(
            "SELECT filename FROM files WHERE id IN ( SELECT image FROM rooms WHERE token = ? LIMIT 1 ) LIMIT 1",
            [room_id],
        )
        row = result.fetchone()
        if row:
            filename = row[0]
    if filename and os.path.exists(filename):
        with open(filename, 'rb') as f:
            return {'status_code': 200, "result": b64encode(f.read())}
    else:
        return {"status_code": 404}


def get_mods_for_room(room_id, curr_session_id=None):
    """
    Returns a list of session_ids who are moderators of the room.

    `curr_session_id` is the current user's session id, and controls how we return hidden
    moderators: if the given user is an admin then all hidden mods/admins are included.  If the
    given user is a moderator then we include that specific user in the mod list if she is a
    moderator, but don't include any other hidden mods/admins.
    """

    we_are_hidden, we_are_admin = False, False
    mods, hidden_mods = [], []
    from .web import app

    for session_id, visible, admin in db.conn.execute(
        "SELECT session_id, visible_mod, admin FROM user_permissions WHERE room = ? AND moderator",
        [room_id],
    ):
        if session_id is not None and session_id == curr_session_id:
            we_are_hidden = not visible
            we_are_admin = admin

        (mods if visible else hidden_mods).append(session_id)

    if we_are_admin:
        mods += hidden_mods
    elif we_are_hidden:
        mods.append(curr_session_id)

    return mods


def get_deletions_deprecated(room_id, since):
    with db.conn as conn:
        if since:
            result = conn.execute(
                "SELECT id, updated FROM messages WHERE room = ? AND updated > ? AND data IS NULL ORDER BY updated ASC LIMIT 256",
                [room_id, since],
            )
        else:
            result = conn.execute(
                "SELECT id, updated FROM messages WHERE room = ? AND data IS NULL ORDER BY updated DESC LIMIT 256",
                [room_id],
            )
        return [{'deleted_message_id': row[0], 'id': row[1]} for row in result]


def get_message_deprecated(room_id, since, limit=256):
    msgs = list()
    with db.conn as conn:
        result = None
        if since:
            result = conn.execute(
                "SELECT * FROM message_details WHERE room = ? AND id > ? AND data IS NOT NULL ORDER BY id ASC LIMIT ?",
                [room_id, since, limit],
            )
        else:
            result = conn.execute(
                "SELECT * FROM message_details WHERE room = ? AND data IS NOT NULL ORDER BY id DESC LIMIT ?",
                [room_id, limit],
            )
        for row in result:
            data = row['data']
            data_size = row['data_size']
            if len(data) < data_size:
                # Re-pad the message (we strip off padding when storing)
                data += b'\x00' * (data_size - len(data))

            msgs.append(
                {
                    'server_id': row[0],
                    'public_key': row[-1],
                    'timestamp': utils.convert_time(row['posted']),
                    'data': utils.encode_base64(data),
                    'signature': utils.encode_base64(row['signature']),
                }
            )
    return msgs
