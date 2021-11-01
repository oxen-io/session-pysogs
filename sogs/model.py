from . import db

from base64 import b64encode

import os

def get_rooms():
    """ get a list of rooms with their full info filled out """
    rooms = list()
    with db.pool as conn:
        result = conn.execute("SELECT token, name, description, image, created, updates, read, write, upload FROM rooms ORDER BY token")
        for row in result:
            room_info = dict()
            cols = list(row)
            for key in ['token', 'name', 'description', 'image', 'created', 'updates', 'read', 'write', 'upload']:
                room_info[key] = cols[0]
                cols.pop(0)
            room_info['id'] = room_info['token']
            rooms.append(room_info)
    return rooms


def get_room(room_id):
    with db.pool as conn:
        result = conn.execute("SELECT token, name, description, image, created, updates, read, write, upload FROM rooms WHERE token=? LIMIT 1", [room_id])
        row = result.fetchone()
        if row:
            cols = list(row)
            room_info = dict()
            for key in ['token', 'name', 'description', 'image', 'created', 'updates', 'read', 'write', 'upload']:
                room_info[key] = cols[0]
                cols.pop(0)
            room_info['id'] = room_info['token']
            return room_info
    

def get_user(session_id):
    """ get a user by their session id """
    with db.pool as conn:
        result = conn.execute("SELECT * FROM users WHERE session_id = ? LIMIT 1", [session_id])
        row = None
        try:
            row = result.fetchone()
        except:
            return
        user = dict()
        for k in row.keys():
            user[k] = row[k]
        return user


def add_post_to_room(user_id, room_id, data, sig):
    """ insert a post into a room from a user """
    with db.pool as conn:
        conn.execute("INSERT INTO messages(user, room, data, signature) VALUES(?, ?, ?, ?)", user_id, room_id, data, sig)


def get_room_image_json_blob(room_id):
    """ return a json object with base64'd file contents for the image of a room """
    filename = None
    with db.pool as conn:
        # todo: this query sucks
        result = conn.execute("SELECT filename FROM files WHERE id IN ( SELECT image FROM rooms WHERE token = ? LIMIT 1 ) LIMIT 1", [room_id])
        row = result.fetchone()
        if row:
            filename = row[0]
    if filename and os.path.exists(filename):
        with open(filename, 'rb') as f:
            return {'status_code': 200, "result": b64encode(f.read())}
    else:
        return {"status_code": 404}

def get_mods_for_room(room_id):
    mods = list()
    with db.pool as conn:
        result = conn.execute("SELECT session_id FROM user_permissions WHERE room = ? AND moderator AND visible_mod", [room_id])
        for row in result:
            mods.append(row[0])
    return mods


def get_deletions_deprecated(room_id, since):
    msgs = list()
    with db.pool as conn:
        result = None
        if since:
            result = conn.execute("SELECT id, updated FROM messages WHERE room = ? AND updated > ? AND data IS NULL ORDER BY updated LIMIT 256", room_id, since)
        else:
            result = conn.execute("SELECT id, updated FROM messages WHERE room = ? AND data IS NULL ORDER BY updated DESC LIMIT 256", [room_id])
        for row in result:
            msgs.append({'id': row[0], 'updated': row[1]})
    return msgs

def get_message_deprecated(room_id, since):
    msgs = list()
    with db.pool as conn:
        result = None
        if since:
            result = conn.execute("SELECT * FROM message_details WHERE room = ? AND id > ? AND data IS NOT NULL ORDER BY id LIMIT 256", [room_id])
        else:
            result = conn.execute("SELECT * FROM message_details WHERE room = ? AND data IS NOT NULL ORDER BY id DESC LIMIT 256", room_id, since)
        for row in result:
            msgs.append({'server_id': row[0], 'public_key': row[-1], 'timestamp': row[3], 'data': row[6], 'signature': row[8]})
    return msgs
