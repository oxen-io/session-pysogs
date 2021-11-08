from . import config
from . import db
from . import utils

import os
import time


class NoSuchRoom(LookupError):
    """Thrown when trying to construct a Room from a token that doesn't exist"""

    def __init__(self, token):
        self.token = token
        super().__init__("No such room: {}".format(token))


class NoSuchFile(LookupError):
    """Thrown when trying to construct a File from a token that doesn't exist"""

    def __init__(self, id):
        self.id = id
        super().__init__("No such file: {}".format(id))


class NoSuchUser(LookupError):
    """Thrown when attempting to retrieve a user that doesn't exist and auto-vivification of the
    user room is disabled"""

    def __init__(self, session_id):
        self.session_id = session_id
        super().__init__("No such user: {}".format(session_id))


class Room:
    """
    Class representing a room stored in the database.

    Properties:
        id - the numeric room id, i.e. the database primary key
        token - the alphanumeric room token
        name - the public name of the room
        description - a description of the room
        image - the Image object for this room's image, if set; None otherwise.  (Note that the
            Image is not query/loaded until wanted).
        created - unix timestamp when the room was created
        updates - the room message activity counter; this is automatically incremented for each new
            message, edit, or deletion in the room and is used by clients to query message updates.
        info_updates - counter on room metadata that is automatically incremented whenever room
            metadata (name, description, image, etc.) changes for the room.
        default_read - True if default user permissions includes read permission
        default_write - True if default user permissions includes write permission
        default_upload - True if default user permissions includes file upload permission
    """

    def __init__(self, row=None, *, id=None, token=None):
        """
        Constructs a room from a pre-retrieved row *or* via lookup of a room token or id.  When
        looking up this raises a KeyError if no room with that token/id exists.
        """
        if sum(x is not None for x in (row, id, token)) != 1:
            raise ValueError("Room() error: exactly one of row/id/token must be specified")
        if token is not None:
            row = db.conn.execute("SELECT * FROM rooms WHERE token = ?", (token,)).fetchone()
        elif id is not None:
            row = db.conn.execute("SELECT * FROM rooms WHERE id = ?", (id,)).fetchone()
        if not row:
            raise NoSuchRoom(token if token is not None else id)

        (
            self.id,
            self.token,
            self.name,
            self.description,
            self._fetch_image_id,
            self.created,
            self.updates,
            self.info_updates,
        ) = (
            row[c]
            for c in (
                'id',
                'token',
                'name',
                'description',
                'image',
                'created',
                'updates',
                'info_updates',
            )
        )
        self.default_read, self.default_write, self.default_upload = (
            bool(row[c]) for c in ('read', 'write', 'upload')
        )
        self._image = None  # Retrieved on demand

    @property
    def image(self):
        """
        Accesses the room image File for this room; this is fetched from the database the first time
        this is accessed.
        """
        if self._fetch_image_id is not None:
            try:
                self._image = File(id=self._fetch_image_id)
            except NoSuchFile:
                pass
            self._fetch_image_id = None
        return self._image

    def active_users(self, cutoff=config.ROOM_DEFAULT_ACTIVE_THRESHOLD * 86400):
        """
        Queries the number of active users in the past `cutoff` seconds.  Defaults to
        config.ROOM_DEFAULT_ACTIVE_THRESHOLD days.  Note that room activity records are periodically
        removed, so going beyond config.ROOM_ACTIVE_PRUNE_THRESHOLD days is useless.
        """

        return db.conn.execute(
            "SELECT COUNT(*) FROM room_users WHERE room = ? AND last_active >= ?",
            (self.id, time.time() - cutoff),
        ).fetchone()[0]


class File:
    """
    Class representing a user stored in the database.

    Properties:
        id - the numeric file id, i.e. primary key
        room - the Room that this file belongs to (only retrieved on demand).
        uploader - the User that uploaded this file (only retrieved on demand).
        size - the size (in bytes) of this file
        uploaded - unix timestamp when the file was uploaded
        expiry - unix timestamp when the file expires.  None for non-expiring files.
        path - the path of this file on disk, relative to the base data directory.
        filename - the suggested filename provided by the user.  None for there is no suggestion
            (this will always be the case for files uploaded by legacy Session clients).
    """

    def __init__(self, row=None, *, id=None):
        """
        Constructs a file from a pre-retrieved row *or* a file id.  Raises NoSuchFile if the id does
        not exist in the database.
        """
        if sum(x is not None for x in (id, row)) != 1:
            raise ValueError("File() error: exactly one of id/row is required")
        if id is not None:
            row = db.conn.execute("SELECT * FROM files WHERE id = ?", (id,)).fetchone()
            if not row:
                raise NoSuchFile(id)

        (
            self.id,
            self._fetch_room_id,
            self.uploader,
            self.size,
            self.uploaded,
            self.expiry,
            self.filename,
            self.path,
        ) = (
            row[c]
            for c in ('id', 'room', 'uploader', 'size', 'uploaded', 'expiry', 'filename', 'path')
        )
        self._room = None

    @property
    def room(self):
        """
        Accesses the Room in which this image is posted; this is fetched from the database the first
        time this is accessed.  In theory this can return None if the Room is in the process of
        being deleted but the Room's uploaded files haven't been deleted yet.
        """
        if self._fetch_room_id is not None:
            try:
                self._room = Room(id=self._fetch_room_id)
            except NoSuchFile:
                pass
            self._fetch_room_id = None
        return self._room

    def read(self):
        """Reads the file from disk, as bytes."""
        with open(self.path, 'rb') as f:
            return f.read()

    def read_base64(self):
        """Reads the file from disk and encodes as base64."""
        return utils.encode_base64(self.read())


class User:
    """
    Class representing a user stored in the database.

    Properties:
        id - the database primary key for this user row
        session_id - the session_id of the user, in hex
        created - unix timestamp when the user was created
        last_active - unix timestamp when the user was last active
        banned - True if the user is (globally) banned
        admin - True if the user is a global admin
        moderator - True if the user is a global moderator
        visible_mod - True if the user's admin/moderator status should be visible in rooms
    """

    def __init__(self, row=None, *, id=None, session_id=None, autovivify=True, touch=False):
        """
        Constructs a user from a pre-retrieved row *or* a session id or user primary key value.

        autovivify - if True and we are given a session_id that doesn't exist, create a default user
        row and use it to populate the object.  This is the default behaviour.  If False and the
        session_id doesn't exist then a NoSuchUser is raised if the session id doesn't exist.

        touch - if True (default is False) then update the last_activity time of this user before
        returning it.
        """

        if sum(x is not None for x in (row, session_id, id)) != 1:
            raise ValueError("User() error: exactly one of row/session_id/id is required")

        with db.conn as conn:
            self._touched = False
            if session_id is not None:
                row = db.conn.execute(
                    "SELECT * FROM users WHERE session_id = ?", (session_id,)
                ).fetchone()

                if not row and autovivify:
                    with conn as db.conn:
                        conn.execute("INSERT INTO users (session_id) VALUES (?)", (session_id,))
                        row = conn.execute(
                            "SELECT * FROM users WHERE session_id = ?", (session_id,)
                        ).fetchone()
                        # No need to re-touch this user since we just created them:
                        self._touched = True

            elif id is not None:
                row = db.conn.execute("SELECT * FROM users WHERE id = ?", (id,)).fetchone()

            if row is None:
                raise NoSuchUser(session_id if session_id is not None else id)

            self.id, self.session_id, self.created, self.last_active = (
                row[c] for c in ('id', 'session_id', 'created', 'last_active')
            )
            self.banned, self.global_moderator, self.global_admin, self.visible_mod = (
                bool(row[c]) for c in ('banned', 'moderator', 'admin', 'visible_mod')
            )

            if touch:
                self._touch()

    def _touch(self):
        db.conn.execute(
            """
            UPDATE users SET last_active = ((julianday('now') - 2440587.5)*86400.0)
            WHERE id = ?
            """,
            (self.id,),
        )
        self._touched = True

    def touch(self, force=False):
        """
        Updates the last activity time of this user.  This method only updates the first time it is
        called (and possibly not even then, if we auto-vivified the user row), unless `force` is set
        to True.
        """
        if not self._touched or force:
            with db.conn:
                self._touch()


def get_rooms():
    """get a list of all rooms"""
    with db.conn as conn:
        result = conn.execute("SELECT * FROM rooms ORDER BY token")
        return [Room(row) for row in result]


def get_readable_rooms(pubkey):
    """get a list of rooms that a user can access"""
    with db.conn as conn:
        result = conn.execute(
            "SELECT rooms.* FROM user_permissions perm JOIN rooms ON rooms.id = room WHERE session_id = ? AND perm.read AND NOT perm.banned",
            [pubkey],
        )
        return [Room(row) for row in result]


def check_permission(
    user, room, *, admin=False, moderator=False, read=False, write=False, upload=False
):
    """
    Checks whether `user` has the required permissions for room `room`, and isn't banned.  Returns
    True if the user satisfies the permissions, false otherwise.  `user` can be either a session_id
    string, or a User instance; `room` can either be a Room instance or a numeric room id (but not a
    room token).

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

    if not isinstance(user, User):
        user = User(session_id=user, autovivify=True, touch=True)
    user.touch()

    result = db.conn.execute(
        """
        SELECT banned, read, write, upload, moderator, admin FROM user_permissions
        WHERE room = ? AND user = ?
        """,
        [room.id if isinstance(room, Room) else room, user.id],
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
                """
                SELECT id, updated FROM messages
                WHERE room = ? AND updated > ? AND data IS NULL
                ORDER BY updated ASC LIMIT 256
                """,
                [room_id, since],
            )
        else:
            result = conn.execute(
                """
                SELECT id, updated FROM messages
                WHERE room = ? AND data IS NULL
                ORDER BY updated DESC LIMIT 256
                """,
                [room_id],
            )
        return [{'deleted_message_id': row[0], 'id': row[1]} for row in result]


def get_message_deprecated(room_id, since, limit=256):
    msgs = list()
    with db.conn as conn:
        result = None
        if since:
            result = conn.execute(
                """
                SELECT * FROM message_details
                WHERE room = ? AND id > ? AND data IS NOT NULL
                ORDER BY id ASC LIMIT ?
                """,
                [room_id, since, limit],
            )
        else:
            result = conn.execute(
                """
                SELECT * FROM message_details
                WHERE room = ? AND data IS NOT NULL
                ORDER BY id DESC LIMIT ?
                """,
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
