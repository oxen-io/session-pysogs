from __future__ import annotations

from typing import Optional, Union
import flask

from . import config
from . import db
from . import utils
from . import crypto
from . import filtration
from . import http
from .omq import send_mule
from .web import app

import os
import re
import time


class NotFound(LookupError):
    """Base class for NoSuchRoom, NoSuchFile, etc."""

    pass


class NoSuchRoom(NotFound):
    """Thrown when trying to construct a Room from a token that doesn't exist"""

    def __init__(self, token):
        self.token = token
        super().__init__(f"No such room: {token}")


class NoSuchFile(NotFound):
    """Thrown when trying to construct a File from a token that doesn't exist"""

    def __init__(self, id):
        self.id = id
        super().__init__(f"No such file: {id}")


class NoSuchUser(NotFound):
    """Thrown when attempting to retrieve a user that doesn't exist and auto-vivification of the
    user room is disabled"""

    def __init__(self, session_id):
        self.session_id = session_id
        super().__init__(f"No such user: {session_id}")


class BadPermission(RuntimeError):
    """Thrown when attempt to perform an action that the given user does not have permission to do;
    for example, attempting to delete someone else's posts when not a moderator."""

    def __init__(self, msg=None):
        super().__init__("Permission denied" if msg is None else msg)


class PostRejected(RuntimeError):
    """
    Thrown when a post is refused for some reason other than a permission error (e.g. the post
    contains bad words)
    """

    def __init__(self, msg=None):
        super().__init__("Post rejected" if msg is None else msg)


class PostRateLimited(PostRejected):
    """Thrown when attempting to post too frequently in a room"""

    def __init__(self, msg=None):
        super().__init__("Rate limited" if msg is None else msg)


# Map uncaught model exceptions into flask http exceptions
@app.errorhandler(NotFound)
def abort_bad_room(e):
    flask.abort(http.NOT_FOUND)


@app.errorhandler(BadPermission)
def abort_perm_denied(e):
    flask.abort(http.FORBIDDEN)


@app.errorhandler(PostRejected)
def abort_post_rejected(e):
    flask.abort(http.TOO_MANY_REQUESTS)


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
        looking up this raises a NoSuchRoom if no room with that token/id exists.
        """
        if sum(x is not None for x in (row, id, token)) != 1:
            raise ValueError("Room() error: exactly one of row/id/token must be specified")
        if token is not None:
            row = db.execute("SELECT * FROM rooms WHERE token = ?", (token,)).fetchone()
        elif id is not None:
            row = db.execute("SELECT * FROM rooms WHERE id = ?", (id,)).fetchone()
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
        self._perm_cache = {}

    def __str__(self):
        """Returns `Room[token]` when converted to a str"""
        return f"Room[{self.token}]"

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

    @property
    def info(self):
        """a dict containing all info needed for serializing a room over zmq"""
        return {'id': self.id, 'token': self.token}

    def active_users(self, cutoff=config.ROOM_DEFAULT_ACTIVE_THRESHOLD * 86400):
        """
        Queries the number of active users in the past `cutoff` seconds.  Defaults to
        config.ROOM_DEFAULT_ACTIVE_THRESHOLD days.  Note that room activity records are periodically
        removed, so going beyond config.ROOM_ACTIVE_PRUNE_THRESHOLD days is useless.
        """

        return db.execute(
            "SELECT COUNT(*) FROM room_users WHERE room = ? AND last_active >= ?",
            (self.id, time.time() - cutoff),
        ).fetchone()[0]

    def check_permission(
        self,
        user: Optional[User],
        *,
        admin=False,
        moderator=False,
        read=False,
        write=False,
        upload=False,
    ):
        """
        Checks whether `user` has the required permissions for this room and isn't banned.  Returns
        True if the user satisfies the permissions, false otherwise.  If no user is provided then
        permissions are checked against the room's defaults.

        Looked up permissions are cached within the Room instance so that looking up the same user
        multiple times (i.e. from multiple parts of the code) does not re-query the database.

        Named arguments are as follows:
        - admin -- if true then the user must have admin access to the room
        - moderator -- if true then the user must have moderator (or admin) access to the room
        - read -- if true then the user must have read access
        - write -- if true then the user must have write access
        - upload -- if true then the user must have upload access; this should usually be combined
          with write=True.

        You can specify multiple permissions as True, in which case all must be satisfied.  If you
        specify no permissions as required then the check only checks whether a user is banned but
        otherwise requires no specific permission.
        """

        if user is None:
            is_banned, can_read, can_write, can_upload, is_mod, is_admin = (
                False,
                self.default_read,
                self.default_write,
                self.default_upload,
                False,
                False,
            )
        else:
            if user.id not in self._perm_cache:
                row = db.execute(
                    """
                    SELECT banned, read, write, upload, moderator, admin FROM user_permissions
                    WHERE room = ? AND user = ?
                    """,
                    [self.id, user.id],
                ).fetchone()
                self._perm_cache[user.id] = list(row)

            is_banned, can_read, can_write, can_upload, is_mod, is_admin = self._perm_cache[user.id]

        if is_admin:
            return True
        if admin:
            return False
        if is_mod:
            return True
        if moderator:
            return False
        return (
            not is_banned
            and (not read or can_read)
            and (not write or can_write)
            and (not upload or can_upload)
        )

    # Shortcuts for check_permission calls

    def check_unbanned(self, user: User):
        return self.check_permission(user)

    def check_read(self, user: Optional[User]):
        return self.check_permission(read=True)

    def check_write(self, user: Optional[User]):
        return self.check_permission(write=True)

    def check_upload(self, user: Optional[User]):
        """Checks for both upload *and* write permission"""
        return self.check_permission(write=True, upload=True)

    def check_moderator(self, user: User):
        return self.check_permission(user, moderator=True)

    def check_admin(self, user: User):
        return self.check_permission(user, admin=True)

    def messages_size(self):
        """Returns the number and total size (in bytes) of non-deleted messages currently stored in
        this room.  Size is reflects the size of uploaded message bodies, not necessarily the size
        actually used to store the message, and does not include various ancillary metadata such as
        edit history, the signature, deleted entries, etc."""
        return db.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(data_size), 0)
            FROM messages
            WHERE room = ? AND data IS NOT NULL
            """,
            (self.id,),
        ).fetchone()[0:2]

    def get_messages_for(
        self,
        user: Optional[User],
        *,
        after: int = None,
        before: int = None,
        recent: bool = False,
        limit: int = 256,
    ):
        """
        Returns up to `limit` messages that `user` should see: that is, all non-deleted room
        messages plus any whispers directed to the user and, if the user is a moderator, any
        whispers meant to be displayed to moderators.

        Exactly one of `after`, `begin`, or `recent` must be specified: `after=N` returns messages
        with ids greater than N in ascending order; `before=N` returns messages with ids less than N
        in descending order; `recent=True` returns the most recent messages in descending order.

        Note that data and signature are returned as bytes, *not* base64 encoded.  Session message
        padding *is* appended to the data field (i.e. this returns the full value, not the
        padding-trimmed value actually stored in the database).
        """

        mod = self.check_moderator(user)
        msgs = []

        opt_count = sum((after is not None, before is not None, recent))
        if opt_count == 0:
            raise RuntimeError("Exactly one of before=, after=, or recent= is required")
        if opt_count > 1:
            raise RuntimeError("Cannot specify more than one of before=, after=, recent=")

        # Handle id mapping from an old database import in case the client is requesting
        # messages since some id from the old db.
        if after is not None and db.ROOM_IMPORT_HACKS and self.id in db.ROOM_IMPORT_HACKS:
            max_old_id, offset = db.ROOM_IMPORT_HACKS[self.id]
            if after <= max_old_id:
                after += offset

        for row in db.execute(
            f"""
            SELECT * FROM message_details
            WHERE room = ? AND data IS NOT NULL
                {'AND id > ?' if after else 'AND id < ?' if before else ''}
                AND (
                    whisper IS NULL
                    {'OR whisper = ?' if user else ''}
                    {'OR whisper_mods' if mod else ''}
                )
            ORDER BY id {'ASC' if after is not None else 'DESC'} LIMIT ?
            """,
            (
                self.id,
                *(() if recent else (after,) if after is not None else (before,)),
                *((user.id,) if user else ()),
                limit,
            ),
        ):
            data = utils.add_session_message_padding(row['data'], row['data_size'])
            msg = {x: row[x] for x in ('id', 'session_id', 'posted', 'updated', 'signature')}
            msg['data'] = data
            if row['edited'] is not None:
                msg['edited'] = row['edited']
            if row['whisper_to'] is not None or row['whisper_mods']:
                msg['whisper'] = True
                msg['whisper_mods'] = row['whisper_mods']
                if row['whisper_to'] is not None:
                    msg['whisper_to'] = row['whisper_to']
            msgs.append(msg)

        return msgs

    def add_post(
        self,
        user: User,
        data: bytes,
        sig: bytes,
        *,
        whisper_to: Optional[Union[User, str]] = None,
        whisper_mods: bool = False,
    ):
        """
        Adds a post to the room.  The user must have write permissions.

        Raises BadPermission() if the user doesn't have posting permission; PostRejected() if the
        post was rejected (such as subclass PostRateLimited() if the post was rejected for too
        frequent posting).

        Returns the message details.
        """
        if not self.check_write(user):
            raise BadPermission()

        whisper_mods = bool(whisper_mods)
        if (whisper_to or whisper_mods) and not self.check_moderator(user):
            app.logger.warn(f"Cannot post a whisper to {self}: {user} is not a moderator")
            raise BadPermission()

        if not isinstance(whisper_to, User):
            whisper_to = User(session_id=whisper_to, autovivify=True, touch=False)

        if not self.check_admin(user) and filtration.should_drop_message_with_body(data):
            raise PostRejected("filtration rejected message")

        with db.tx() as cur:
            if not self.check_admin(user):

                # TODO: These really should be room properties, not random global constants (these
                # are carried over from old SOGS).
                rate_limit_size = 5
                rate_limit_interval = 16.0

                since_limit = time.time() - rate_limit_interval
                result = cur.execute(
                    "SELECT COUNT(*) FROM messages WHERE room = ? AND user = ? AND posted >= ?",
                    (self.id, user.id, since_limit),
                )

                row = result.fetchone()
                if row[0] >= rate_limit_size:
                    raise PostRateLimited()

            data_size = len(data)
            unpadded_data = utils.remove_session_message_padding(data)

            result = cur.execute(
                """
                INSERT INTO messages
                    (room, user, data, data_size, signature, whipser_to, whisper_mods)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (self.id, user.id, unpadded_data, data_size, sig, whisper_to.id, whisper_mods),
            )
            msg_id = result.lastrowid
            row = cur.execute(
                "SELECT posted, updated FROM messages WHERE id = ?", (msg_id,)
            ).fetchone()
            msg = {
                'id': msg_id,
                'session_id': user.session_id,
                'posted': row[0],
                'updated': row[1],
                'data': data,
                'signature': sig,
            }
            if whisper_to or whisper_mods:
                msg['whisper'] = True
                msg['whisper_mods'] = whisper_mods
                if whisper_to:
                    msg['whisper_to'] = whisper_to.session_id

        send_mule("message_posted", msg['id'])
        return msg

    def delete_posts(self, message_ids: list[int], deleter: User):
        """
        Deletes the messages with the given ids.  The given user performing the delete must be a
        moderator of the room.

        Returns the ids actually deleted (that is, already-deleted and non-existent ids are not
        returned).

        Throws BadPermission (without deleting anything) if attempting to delete any posts that the
        given user does not have permission to delete.
        """

        deleted = []
        i = 0
        with db.tx() as cur:
            # Process in slices of 50 (in case we're given more than 50) because that's a lot of
            # parameters to bind and we want to avoid hitting bind limits.
            while i < len(message_ids):
                n_ids = min(len(message_ids) - i, 50)

                # First filter out ids that are already deleted (e.g. because of a race condition of
                # multiple mods) or that aren't part of the room.  It wouldn't hurt the query to
                # "delete" them again, but we want to avoid passing them to the mule multiple times.
                ids = [
                    r[0]
                    for r in cur.execute(
                        f"""
                        SELECT id FROM messages WHERE room = ? AND data IS NOT NULL
                            AND id IN ({','.join('?' * n_ids)})
                        """,
                        [self.id, *message_ids[i : i + 50]],
                    )
                ]

                if ids:
                    id_in = "id IN ({})".format(','.join('?' * len(ids)))

                    if not self.check_moderator(deleter):
                        # If not a moderator then we only proceed if all of the messages are the
                        # user's own:
                        res = cur.execute(
                            f"SELECT EXISTS( SELECT * FROM messages WHERE user != ? AND {id_in} )",
                            [deleter.id, *ids],
                        )
                        if res.fetchone()[0]:
                            raise BadPermission()

                    cur.execute(f"DELETE FROM message_details WHERE {id_in}", ids)

                    deleted += ids
                i += 50

        return deleted

    def delete_all_posts(self, poster: User, *, deleter: User):
        """
        Delete all posts and attachments made by `poster` from the room.  `deleter` must be a
        moderator if not deleting his/her own posts, and must be an `admin` if trying to delete all
        of the posts of another admin.
        """

        fail = None
        if poster.id != deleter.id and not self.check_moderator(deleter):
            fail = "user is not a moderator"
        elif self.check_admin(poster) and not self.check_admin(deleter):
            fail = "only admins can delete all posts of another admin"

        if fail is not None:
            app.logger.warn(
                f"Error deleting all posts by {poster} from {self} by {deleter}: {fail}"
            )
            raise BadPermission()

        with db.tx() as cur:
            deleted = [
                r[0]
                for r in cur.execute(
                    "SELECT id FROM messages WHERE room = ? AND user = ? AND data IS NOT NULL",
                    (self.id, poster.id),
                )
            ]

            cur.execute(
                "DELETE FROM message_details WHERE room = ? AND user = ?", (self.id, poster.id)
            )

            # Set up files for deletion, but don't wipe out the room image in case the target was
            # the one who uploaded it:
            image = self.image
            omit_id = image.id if image.uploader == poster.id else None

            # TODO: Eventually we can drop this: once uploads have to be properly associated with
            # posts then the post deletion should trigger automatic expiry of post attachments.

            # Don't actually delete right now but set room to NULL so that the images aren't
            # retrievable, and set expiry to now so that they'll be picked up by the next db
            # cleanup.
            cur.execute(
                f"""
                UPDATE files SET room = NULL, expiry = ? WHERE room = ? AND uploader = ?
                    {'AND id != ?' if omit_id else ''}
                """,
                (time.time(), self.id, poster.id, *((omit_id,) if omit_id else ())),
            )
            files_removed = cur.rowcount

        # FIXME: send `deleted` to mule

        app.logger.debug(
            f"Delete all posts by {poster} from {self}: {len(deleted)} posts, {files_removed} files"
        )

        return len(deleted), files_removed

    def attachments_size(self):
        """Returns the number and aggregate size of attachments currently stored in this room"""
        return db.execute(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files WHERE room = ?", (self.id,)
        ).fetchone()[0:2]

    def get_mods(self, user=None):
        """
        Returns a list of session_ids who are moderators of the room, with permission checking.

        `user` is the current User or the user's session id, and controls how we return hidden
        moderators: if the given user is an admin then all hidden mods/admins are included.  If the
        given user is a moderator then we include that specific user in the mod list if she is a
        moderator, but don't include any other hidden mods/admins.

        If user is None then we don't include any hidden mods.
        """

        we_are_hidden, we_are_admin = False, False
        mods, hidden_mods = [], []

        curr_session_id = (
            None if user is None else user.session_id if isinstance(user, User) else user
        )

        for session_id, visible, admin in db.execute(
            """
            SELECT session_id, visible_mod, admin FROM user_permissions
            WHERE room = ? AND moderator
            """,
            [self.id],
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

    def get_all_moderators(self):
        """Returns a tuple of lists of all moderators and admins of the room.  This only includes
        direct room admins/mods, not global mods/admins.  This is not meant to be user-facing; use
        get_mods() for that instead.

        Returns a tuple of 4 lists:

        - visible mods
        - visible admins
        - hidden mods
        - hidden admins
        """

        m, hm, a, ha = [], [], [], []
        for session_id, visible, admin in db.execute(
            """
            SELECT session_id, o.visible_mod, o.admin
            FROM user_permission_overrides o JOIN users ON o.user = users.id
            WHERE room = ? AND o.moderator
            """,
            [self.id],
        ):
            ((a if admin else m) if visible else (ha if admin else hm)).append(session_id)

        return (m, a, hm, ha)

    def set_moderator(self, user: User, *, added_by: User, admin=False, visible=True):
        """
        Sets `user` as a moderator or admin of this room.  Replaces current admin/moderator/visible
        status with the new values if the user is already a moderator/admin of the room.

        added_by is the user performing the update and must have admin permission.
        """

        if not self.check_admin(added_by):
            app.logger.warn(
                f"Unable to set {user} as {'admin' if admin else 'moderator'} of {self}: "
                f"{added_by} is not an admin"
            )
            raise BadPermission()

        db.execute(
            """
            INSERT INTO user_permission_overrides (room, user, moderator, admin, visible_mod)
            VALUES (?, ?, TRUE, ?, ?)
            ON CONFLICT (room, user) DO UPDATE SET
                moderator = excluded.moderator,
                admin = excluded.admin,
                visible_mod = excluded.visible_mod
            """,
            (self.id, user.id, admin, visible),
        )

        app.logger.info(f"{added_by} set {user} as {'admin' if admin else 'moderator'} of {self}")

    def remove_moderator(self, user: User, *, removed_by: User):
        """Remove `user` as a moderator/admin of this room.  Requires admin permission."""

        if not self.check_admin(removed_by):
            raise BadPermission()

        db.execute(
            """
            UPDATE user_permission_overrides
            SET moderator = FALSE, admin = FALSE, visible_mod = TRUE
            WHERE room = ? AND user = ?
            """,
            (self.id, user.id),
        )

        app.logger.info(f"{removed_by} removed {user} as mod/admin of {self}")

    def ban_user(self, to_ban: User, *, mod: User, timeout: Optional[float] = None):
        """
        Adds a ban to this room of `to_ban`, banned by `mod`, with the ban lasting for `timeout`
        seconds (or forever, if timeout is omitted or None).

        Raises BadPermission is the given `mod` is lacking the required permission to institute the
        ban (i.e. not-a-moderator, or not-an-admin if trying to ban a room moderator/admin, or
        trying to ban a global mod/admin from a room).
        """

        fail = None
        if not self.check_moderator(mod):
            fail = "user is not a moderator"
        elif to_ban.id == mod.id:
            fail = "self-ban not permitted"
        elif to_ban.global_moderator:
            fail = "global mods/admins cannot be banned"
        elif self.check_moderator(to_ban) and not self.check_admin(mod):
            fail = "only admins can ban room mods/admins"

        if fail is not None:
            app.logger.warn(f"Error banning {to_ban} from {self} by {mod}: {fail}")
            raise BadPermission()

        # TODO: log the banning action for auditing

        with db.tx() as cur:
            cur.execute(
                """
                INSERT INTO user_permission_overrides (room, user, banned, moderator, admin)
                    VALUES (?, ?, TRUE, FALSE, FALSE)
                ON CONFLICT (room, user) DO
                    UPDATE SET banned = TRUE, moderator = FALSE, admin = FALSE
                """,
                (self.id, to_ban.id),
            )

            if timeout:
                cur.execute(
                    """
                    INSERT INTO user_permission_futures (room, user, at, banned)
                        VALUES (?, ?, ?, FALSE)
                    """,
                    (self.id, to_ban.id, time.time() + timeout),
                )

        app.logger.debug(f"Banned {to_ban} from {self} (banned by {mod})")

    def unban_user(self, to_unban: User, *, mod: User):
        """
        Removes a user ban from a user, if present.  `mod` must be a moderator.

        Returns true if a ban was removed, false if the user wasn't banned.

        Throws on other errors (e.g. permission denied).
        """

        if not self.check_moderator(mod):
            app.logger.warn(f"Error unbanning {to_unban} from {self} by {mod}: not a moderator")
            raise BadPermission()

        cur = db.cur()
        cur.execute(
            """
            UPDATE user_permission_overrides SET banned = FALSE
            WHERE room = ? AND user = ? AND banned
            """,
            (self.id, to_unban.id),
        )
        if cur.rowcount > 0:
            app.logger.debug(f"{mod} unbanned {to_unban} from {self}")
            return True

        app.logger.debug(f"{mod} unbanned {to_unban} from {self} (but user was already unbanned)")
        return False

    def get_bans(self):
        """
        Retrieves all the session IDs banned from this room.  This does not check permissions: i.e.
        it should only be accessed by moderators/admins.
        """

        return [
            r[0]
            for r in db.execute(
                "SELECT session_id FROM user_permissions WHERE room = ? AND banned", (self.id,)
            )
        ]

    def get_file(self, file_id: int):
        """Retrieves a file uploaded to this room by id.  Returns None if not found."""
        row = db.execute(
            "SELECT * FROM files WHERE room = ? AND id = ?", (self.id, file_id)
        ).fetchone()

        if not row and db.HAVE_FILE_ID_HACKS:
            row = db.execute(
                """
                SELECT * FROM files WHERE id = (
                    SELECT file FROM file_id_hacks WHERE room = ? AND old_file_id = ?
                )
                """,
                (self.id, file_id),
            ).fetchone()

        if row:
            return File(row)
        return None

    def upload_file(
        self,
        content: bytes,
        uploader: User,
        *,
        filename: Optional[str] = None,
        lifetime: Optional[float] = config.UPLOAD_DEFAULT_EXPIRY_DAYS * 86400.0,
    ):
        """
        Uploads a file to this room.  The uploader must have write and upload permissions.

        Arguments:

        - content -- the file content in bytes
        - uploader -- the user who is uploading the file
        - filename -- the filename as provided by the user, or None if no filename provided
        - lifetime -- how long (in seconds) the file should last before expiring; can be None for a
          file that should never expire.

        Returns the id of the newly inserted file row.  Throws on error.
        """

        if not self.check_upload(uploader):
            raise BadPermission()

        files_dir = "uploads/" + self.token
        os.makedirs(files_dir, exist_ok=True)

        if filename is not None:
            filename = re.sub(config.UPLOAD_FILENAME_BAD, "_", filename)

        file_id, file_path = None, None

        try:
            # Begin a transaction; if this context exits with exception we want to roll back the
            # database addition; we catch *outside* the context so that we catch on commit, as well,
            # so that we also clean up the stored file on disk if the transaction fails to commit.
            with db.tx() as cur:
                expiry = None if lifetime is None else time.time() + lifetime

                # Insert the file row first with path='tmp' then come back and update it to the
                # proper path, which we want to base on the resulting file id.
                cur.execute(
                    """
                    INSERT INTO files (room, uploader, size, expiry, filename, path)
                    VALUES (?, ?, ?, ?, ?, 'tmp')
                    """,
                    (self.id, uploader.id, len(content), expiry, filename),
                )

                file_id = cur.lastrowid

                if filename is None:
                    filename = '(unnamed)'

                if len(filename) > config.UPLOAD_FILENAME_MAX:
                    filename = (
                        filename[: config.UPLOAD_FILENAME_KEEP_PREFIX]
                        + "..."
                        + filename[-config.UPLOAD_FILENAME_KEEP_SUFFIX :]
                    )

                file_path = f"{files_dir}/{file_id}_{filename}"

                with open(file_path, 'wb') as f:
                    f.write(content)

                cur.execute("UPDATE files SET path = ? WHERE id = ?", (file_path, file_id))

                return file_id

        except Exception as e:
            app.logger.warn(f"Failed to write/update file {file_path}: {e}")
            if file_path is not None:
                try:
                    os.unlink(file_path)
                except Exception:
                    pass
            raise

    def set_room_image(self, file: Union[File, int]):
        """Sets a room image to a file (can be either the file id, or File instance)"""

        db.execute(
            "UPDATE rooms SET image = ? WHERE id = ?",
            (file.id if isinstance(file, File) else file, self.id),
        )


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
            row = db.execute("SELECT * FROM files WHERE id = ?", (id,)).fetchone()
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

        self._touched = False
        if session_id is not None:
            row = db.execute("SELECT * FROM users WHERE session_id = ?", (session_id,)).fetchone()

            if not row and autovivify:
                with db.tx() as cur:
                    cur.execute("INSERT INTO users (session_id) VALUES (?)", (session_id,))
                    row = cur.execute(
                        "SELECT * FROM users WHERE session_id = ?", (session_id,)
                    ).fetchone()
                # No need to re-touch this user since we just created them:
                self._touched = True

        elif id is not None:
            row = db.execute("SELECT * FROM users WHERE id = ?", (id,)).fetchone()

        if row is None:
            raise NoSuchUser(session_id if session_id is not None else id)

        self.id, self.session_id, self.created, self.last_active = (
            row[c] for c in ('id', 'session_id', 'created', 'last_active')
        )
        self.banned, self.global_moderator, self.global_admin, self.visible_mod = (
            bool(row[c]) for c in ('banned', 'moderator', 'admin', 'visible_mod')
        )

        if touch:
            with db.tx() as cur:
                self._touch(cur)

    def __str__(self):
        """Returns string representation of a user: U[050123…cdef], the id prefixed with @ or % if
        the user is a global admin or moderator, respectively."""
        if len(self.session_id) != 66:
            # Something weird (e.g. the "deleted" id from an old sogs import), just print directly
            return f"U[{self.session_id}]"
        return "U[{}{}…{}]".format(
            '@' if self.global_admin else '%' if self.global_moderator else '',
            self.session_id[:6],
            self.session_id[-4:],
        )

    def _touch(self, cur):
        cur.execute(
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
            with db.tx() as cur:
                self._touch(cur)

    def update_room_activity(self, room):
        db.execute(
            """
            INSERT INTO room_users (user, room) VALUES (?, ?)
            ON CONFLICT(user, room) DO UPDATE
            SET last_active = ((julianday('now') - 2440587.5)*86400.0)
            """,
            (self.id, room.id),
        )

    def set_moderator(self, *, added_by: User, admin=False, visible=False):
        """
        Make this user a global moderator or admin.  If the user is already a global mod/admin then
        their status is updated according to the given arguments (that is, this can promote/demote).
        """

        if not added_by.global_admin:
            app.logger.warn(
                f"Cannot set {self} as global {'admin' if admin else 'moderator'}: "
                f"{added_by} is not a global admin"
            )
            raise BadPermission()

        with db.tx() as cur:
            cur.execute(
                "UPDATE users SET moderator = TRUE, admin = ?, visible_mod = ? WHERE id = ?",
                (admin, visible, self.id),
            )
        self.global_admin = admin
        self.global_moderator = True
        self.visible_mod = visible

    def remove_moderator(self, *, removed_by: User):
        """Removes this user's global moderator/admin status, if set."""

        if not removed_by.global_admin:
            app.logger.warn(
                f"Cannot remove {self} as global mod/admin: {removed_by} is not an admin"
            )
            raise BadPermission()

        with db.tx() as cur:
            cur.execute(
                "UPDATE users SET moderator = FALSE, admin = FALSE WHERE id = ?", (self.id,)
            )
        self.global_admin = False
        self.global_moderator = False


class SystemUser(User):
    """
    User subclasses representing the local system for performing local operations, e.g. from the
    command line.
    """

    def __init__(self):
        super().__init__(session_id="ff" + crypto.server_pubkey_hex)


def get_rooms():
    """get a list of all rooms"""
    result = db.execute("SELECT * FROM rooms ORDER BY token")
    return [Room(row) for row in result]


def get_readable_rooms(pubkey=None):
    """
    Get a list of rooms that a user can access; if pubkey is None then return all publicly readable
    rooms.
    """
    if pubkey is None:
        result = db.execute("SELECT * FROM rooms WHERE read")
    else:
        result = db.execute(
            """
            SELECT rooms.* FROM user_permissions perm JOIN rooms ON rooms.id = room
            WHERE session_id = ? AND perm.read AND NOT perm.banned
            """,
            [pubkey],
        )
    return [Room(row) for row in result]


def get_all_global_moderators():
    """
    Returns all global moderators; for internal user only as this doesn't filter out hidden
    mods/admins.

    Returns a 4-tuple of lists of:
    - visible mods
    - visible admins
    - hidden mods
    - hidden admins
    """

    m, hm, a, ha = [], [], [], []
    for row in db.execute("SELECT * FROM users WHERE moderator"):
        u = User(row=row)
        lst = (a if u.global_admin else m) if u.visible_mod else (ha if u.global_admin else hm)
        lst.append(u)

    return (m, a, hm, ha)


def get_deletions_deprecated(room: Room, since):
    if since:
        result = db.execute(
            """
            SELECT id, updated FROM messages
            WHERE room = ? AND updated > ? AND data IS NULL
            ORDER BY updated ASC LIMIT 256
            """,
            [room.id, since],
        )
    else:
        result = db.execute(
            """
            SELECT id, updated FROM messages
            WHERE room = ? AND data IS NULL
            ORDER BY updated DESC LIMIT 256
            """,
            [room.id],
        )
    return [{'deleted_message_id': row[0], 'id': row[1]} for row in result]
