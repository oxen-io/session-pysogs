from .. import config, crypto, db, utils
from ..db import query
from ..omq import send_mule
from ..web import app
from .user import User
from .file import File
from .exc import (
    NoSuchRoom,
    NoSuchFile,
    NoSuchPost,
    AlreadyExists,
    BadPermission,
    PostRejected,
    PostRateLimited,
)

import os
import re
import sqlalchemy.exc
import time
from typing import Optional, Union, List


# TODO: These really should be room properties, not random global constants (these
# are carried over from old SOGS).
rate_limit_size = 5
rate_limit_interval = 16.0


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
        message_sequence - the room message activity counter; this is automatically incremented for
            each new message, edit, or deletion in the room and is used by clients to poll for
            new/edited/deleted messages.
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
        self._refresh(id=id, token=token, row=row)

    def _refresh(self, *, id=None, token=None, row=None, perms=False):
        """
        Internal method to (re-)fetch details from the database, most importantly the
        message_sequence and info_updates after a room metadata update.

        Must be given exactly one of id/token/row for an initial load; for a refresh all can be None
        (to use self.id).

        If perms is given as true then we also clear the permission cache (and will have to re-fetch
        any permissions when requested); by default we leave it.
        """

        n_args = sum(x is not None for x in (row, id, token))
        if n_args == 0 and hasattr(self, 'id'):
            id = self.id
        elif n_args != 1:
            raise ValueError("Room() error: exactly one of row/id/token must be specified")

        if token is not None:
            row = query("SELECT * FROM rooms WHERE token = :t", t=token).first()
        elif id is not None:
            row = query("SELECT * FROM rooms WHERE id = :id", id=id).first()
        if not row:
            raise NoSuchRoom(token if token is not None else id)

        (
            self.id,
            self._token,
            self._name,
            self._description,
            self._fetch_image_id,
            self.created,
            self.message_sequence,
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
                'message_sequence',
                'info_updates',
            )
        )
        self._default_read, self._default_write, self._default_upload = (
            bool(row[c]) for c in ('read', 'write', 'upload')
        )

        if (
            hasattr(self, '_image')
            and self._image is not None
            and self._image.id == self._fetch_image_id
        ):
            self._fetch_image_id = None  # We're refreshing and the image didn't change
        else:
            self._image = None  # Retrieved on demand

        self._pinned = None  # Re-retrieved on demand

        if perms or not hasattr(self, '_perm_cache'):
            self._perm_cache = {}

    def __str__(self):
        """Returns `Room[token]` when converted to a str"""
        return f"Room[{self.token}]"

    @staticmethod
    def create(token: str, name: str, description: Optional[str] = None):
        """
        Constructs a new room given the token, name, and (optional) description.  Returns a full Row
        object built from the constructed row.

        (This static method does not authenticate).
        """

        try:
            room_id = db.insert_and_get_pk(
                "INSERT INTO rooms(token, name, description) VALUES(:t, :n, :d)",
                "id",
                t=token,
                n=name,
                d=description,
            )
        except sqlalchemy.exc.IntegrityError:
            raise AlreadyExists(f"Room with token '{token}' already exists", Room, token)
        return Room(id=room_id)

    def delete(self):
        """
        Deletes the given room, including all posts, files, etc. within it.  After the call, the
        values of the room object itself (.id, .token, etc.) remain set to their previous values,
        but are stale and no longer reflect an actual database room.  No other methods should be
        called on the room instance (as most assume the state is valid).

        This is permanent and dangerous!

        This method does not authenticate.
        """
        result = query("DELETE FROM rooms WHERE token = :t", t=self.token)
        if result.rowcount != 1:
            raise NoSuchRoom(self.token)

    @property
    def info(self):
        """
        A dict containing the basic room info needed for serializing room details.

        Note that for bt encoding the `created` value is a float and will need to be changed (e.g.
        to microseconds) to be bt-encoding compatible.
        """
        info = {
            'id': self.id,
            'token': self.token,
            'name': self.name,
            'description': self.description,
            'created': self.created,
            'message_sequence': self.message_sequence,
            'info_updates': self.info_updates,
        }
        if self.image_id is not None:
            info['image_id'] = self.image_id

        return info

    @property
    def token(self):
        """Accesses the room token."""
        return self._token

    @token.setter
    def token(self, tok: str):
        """Updates the room token.  Currently breaks any existing client because they have no way to
        get the renamed URL."""

        # Changing the token is effectively moving the room to a new URL, which doesn't actually
        # affect the message_sequence/info_updates because you'll now have to get the new URL
        # somehow anyway, in which case you don't care about the update value changing.  (Currently
        # this is provided for completeness; in order for renamable tokens we'd probably need to add
        # some sort of token tombstone pointing to the renamed room, otherwise updating token is
        # highly destructive).

        with db.transaction():
            query("UPDATE rooms SET token = :t WHERE id = :r", r=self.id, t=tok)
            self._refresh()

    @property
    def name(self):
        """Accesses the room's human-readable name."""
        return self._name

    @name.setter
    def name(self, name: str):
        """Sets the room's human-readable name."""
        with db.transaction():
            query("UPDATE rooms SET name = :n WHERE id = :r", r=self.id, n=name)
            self._refresh()

    @property
    def description(self):
        """Accesses the room's human-readable description."""
        return self._description

    @description.setter
    def description(self, desc):
        """Sets the room's human-readable description."""
        with db.transaction():
            query("UPDATE rooms SET description = :d WHERE id = :r", r=self.id, d=desc)
            self._refresh()

    @property
    def image_id(self):
        """
        Returns the image of of the room's image, or None if it has no image.  Unlike `.image.id`,
        this does not fetch the image row details from the database.
        """
        return self._fetch_image_id if self._image is None else self._image.id

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

    @image.setter
    def image(self, file: Union[File, int]):
        """
        Sets a room image to a file (can be either the file id, or File instance).  If the file
        currently has an expiry it will be updated to non-expiring.

        If the room currently has an image it will be set to expire after the default expiry.
        (Rather than expiring immediately because the image could also be an attachment to some
        post).
        """

        with db.transaction():
            if not isinstance(file, File):
                file = File(id=file)

            file.set_expiry(forever=True)

            if self.image:
                self.image.set_expiry()

            query("UPDATE rooms SET image = :f WHERE id = :r", r=self.id, f=file.id)

            self._fetch_image_id, self._image = None, file

            self._refresh()

    @property
    def pinned_messages(self):
        """
        Accesses the list of pinned messages for this room; this is fetched from the database the
        first time this is accessed.  Each element is a dict such as:
        {"id": 1234, "pinned_at": 1642701309.5007384, "pinned_by": "05123456....."}
        The returned list should not be modified; instead call pin() or unpin() to add/remove pinned
        messages.
        """

        if self._pinned is None:
            self._pinned = [
                {'id': r[0], 'pinned_at': r[1], 'pinned_by': r[2]}
                for r in query(
                    """
                    SELECT message, pinned_at, users.session_id
                    FROM pinned_messages JOIN users ON pinned_by = users.id
                    WHERE room = :r
                    ORDER BY pinned_at
                    """,
                    r=self.id,
                )
            ]

        return self._pinned

    @property
    def default_read(self):
        """Returns True if this room is publicly readable (e.g. by a new user)"""
        return self._default_read

    @property
    def default_write(self):
        """Returns True if this room is publicly writable (e.g. by a new user)"""
        return self._default_write

    @property
    def default_upload(self):
        """Returns True if this room allows public uploads (e.g. by a new user)"""
        return self._default_upload

    @default_read.setter
    def default_read(self, read: bool):
        """Sets the default read permission of the room"""

        with db.transaction():
            query("UPDATE rooms SET read = :read WHERE id = :r", r=self.id, read=read)
            self._refresh(perms=True)

    @default_write.setter
    def default_write(self, write: bool):
        """Sets the default write permission of the room"""

        with db.transaction():
            query("UPDATE rooms SET write = :write WHERE id = :r", r=self.id, write=write)
            self._refresh(perms=True)

    @default_upload.setter
    def default_upload(self, upload: bool):
        """Sets the default upload permission of the room"""

        with db.transaction():
            query("UPDATE rooms SET upload = :upload WHERE id = :r", r=self.id, upload=upload)
            self._refresh(perms=True)

    def active_users(self, cutoff=config.ROOM_DEFAULT_ACTIVE_THRESHOLD * 86400):
        """
        Queries the number of active users in the past `cutoff` seconds.  Defaults to
        config.ROOM_DEFAULT_ACTIVE_THRESHOLD days.  Note that room activity records are periodically
        removed, so going beyond config.ROOM_ACTIVE_PRUNE_THRESHOLD days is useless.
        """

        return query(
            "SELECT COUNT(*) FROM room_users WHERE room = :r AND last_active >= :since",
            r=self.id,
            since=time.time() - cutoff,
        ).first()[0]

    def check_permission(
        self,
        user: Optional[User] = None,
        *,
        admin=False,
        moderator=False,
        read=False,
        write=False,
        upload=False,
    ):
        """
        Checks whether `user` has the required permissions for this room and isn't banned.  Returns
        True if the user satisfies the permissions, False otherwise.  If no user is provided then
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
                bool(self.default_read),
                bool(self.default_write),
                bool(self.default_upload),
                False,
                False,
            )
        else:
            if user.id not in self._perm_cache:
                row = query(
                    """
                    SELECT banned, read, write, upload, moderator, admin FROM user_permissions
                    WHERE room = :r AND "user" = :u
                    """,
                    r=self.id,
                    u=user.id,
                ).first()
                self._perm_cache[user.id] = [bool(c) for c in row]

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

    def check_unbanned(self, user: Optional[User]):
        return self.check_permission(user)

    def check_read(self, user: Optional[User] = None):
        return self.check_permission(user, read=True)

    def check_write(self, user: Optional[User] = None):
        return self.check_permission(user, write=True)

    def check_upload(self, user: Optional[User] = None):
        """Checks for both upload *and* write permission"""
        return self.check_permission(user, write=True, upload=True)

    def check_moderator(self, user: Optional[User]):
        return self.check_permission(user, moderator=True)

    def check_admin(self, user: Optional[User]):
        return self.check_permission(user, admin=True)

    def messages_size(self):
        """Returns the number and total size (in bytes) of non-deleted messages currently stored in
        this room.  Size is reflects the size of uploaded message bodies, not necessarily the size
        actually used to store the message, and does not include various ancillary metadata such as
        edit history, the signature, deleted entries, etc."""
        return list(
            query(
                """
            SELECT COUNT(*), COALESCE(SUM(data_size), 0)
            FROM messages
            WHERE room = :r AND data IS NOT NULL AND NOT filtered
            """,
                r=self.id,
            ).first()[0:2]
        )

    def get_messages_for(
        self,
        user: Optional[User],
        *,
        after: Optional[int] = None,
        before: Optional[int] = None,
        recent: bool = False,
        single: Optional[int] = None,
        limit: int = 256,
    ):
        """
        Returns up to `limit` messages that `user` should see: that is, all non-deleted room
        messages plus any whispers directed to the user and, if the user is a moderator, any
        whispers meant to be displayed to moderators.

        Exactly one of `after`, `begin`, `recent` or `single` must be specified:
        - `after=N` returns messages with ids greater than N in ascending order
        - `before=N` returns messages with ids less than N in descending order
        - `recent=True` returns the most recent messages in descending order
        - `single=123` returns a singleton list containing the single message with the given message
          id, or an empty list if the message doesn't exist or isn't readable by the user.

        Note that data and signature are returned as bytes, *not* base64 encoded.  Session message
        padding *is* appended to the data field (i.e. this returns the full value, not the
        padding-trimmed value actually stored in the database).
        """

        mod = self.check_moderator(user)
        msgs = []

        opt_count = sum((after is not None, before is not None, recent, single is not None))
        if opt_count == 0:
            raise RuntimeError("Exactly one of before=, after=, recent=, or single= is required")
        if opt_count > 1:
            raise RuntimeError("Cannot specify more than one of before=, after=, recent=, single=")

        # Handle id mapping from an old database import in case the client is requesting
        # messages since some id from the old db.
        if after is not None and db.ROOM_IMPORT_HACKS and self.id in db.ROOM_IMPORT_HACKS:
            max_old_id, offset = db.ROOM_IMPORT_HACKS[self.id]
            if after <= max_old_id:
                after += offset

        for row in query(
            f"""
            SELECT * FROM message_details
            WHERE room = :r AND data IS NOT NULL AND NOT filtered
                {
                    'AND id > :after' if after is not None else
                    'AND id < :before' if before is not None else
                    'AND id = :single' if single is not None else
                    ''
                }
                AND (
                    whisper IS NULL
                    {'OR whisper = :user' if user else ''}
                    {'OR whisper_mods' if mod else ''}
                )
            {
                '' if single is not None else
                'ORDER BY id ASC LIMIT :limit' if after is not None else
                'ORDER BY id DESC LIMIT :limit'
            }
            """,
            r=self.id,
            after=after,
            before=before,
            single=single,
            user=user.id if user else None,
            limit=limit,
        ):
            data = utils.add_session_message_padding(row['data'], row['data_size'])
            msg = {x: row[x] for x in ('id', 'session_id', 'posted', 'seqno', 'signature')}
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

    def should_filter(self, user: User, data: bytes):
        """
        Checks a message for profanity (if the profanity filter is enabled).

        - Returns False if this message passes (i.e. didn't trigger the profanity filter, or is
          being posted by an admin to whom the filter doesn't apply).

        Otherwise, depending on the filtering configuration:
        - Returns True if this message should be silently accepted but filtered (i.e. not shown to
          users).
        - Throws PostRejected if the message should be rejected (and rejection passed back to the
          user).
        """
        if config.PROFANITY_FILTER and not self.check_admin(user):
            import better_profanity

            if better_profanity.profanity.contains_profanity(utils.message_body(data)):
                if config.PROFANITY_SILENT:
                    return True
                else:
                    # FIXME: can we send back some error code that makes Session not retry?
                    raise PostRejected("filtration rejected message")
        return False

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
            app.logger.warning(f"Cannot post a whisper to {self}: {user} is not a moderator")
            raise BadPermission()

        if whisper_to and not isinstance(whisper_to, User):
            whisper_to = User(session_id=whisper_to, autovivify=True, touch=False)

        filtered = self.should_filter(user, data)

        with db.transaction():
            if rate_limit_size and not self.check_admin(user):
                since_limit = time.time() - rate_limit_interval
                recent_count = query(
                    """
                    SELECT COUNT(*) FROM messages
                    WHERE room = :r AND "user" = :u AND posted >= :since
                    """,
                    r=self.id,
                    u=user.id,
                    since=since_limit,
                ).first()[0]

                if recent_count >= rate_limit_size:
                    raise PostRateLimited()

            data_size = len(data)
            unpadded_data = utils.remove_session_message_padding(data)

            msg_id = db.insert_and_get_pk(
                """
                INSERT INTO messages
                    (room, "user", data, data_size, signature, filtered, whisper, whisper_mods)
                    VALUES
                    (:r, :u, :data, :data_size, :signature, :filtered, :whisper, :whisper_mods)
                """,
                "id",
                r=self.id,
                u=user.id,
                data=unpadded_data,
                data_size=data_size,
                signature=sig,
                filtered=filtered,
                whisper=whisper_to.id if whisper_to else None,
                whisper_mods=whisper_mods,
            )
            assert msg_id is not None
            row = query("SELECT posted, seqno FROM messages WHERE id = :m", m=msg_id).first()
            msg = {
                'id': msg_id,
                'session_id': user.session_id,
                'posted': row[0],
                'seqno': row[1],
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

    def delete_posts(self, message_ids: List[int], deleter: User):
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
        with db.transaction():
            # Process in slices of 50 (in case we're given more than 50) because that's a lot of
            # parameters to bind and we want to avoid hitting bind limits.
            while i < len(message_ids):
                # First filter out ids that are already deleted (e.g. because of a race condition of
                # multiple mods) or that aren't part of the room.  It wouldn't hurt the query to
                # "delete" them again, but we want to avoid passing them to the mule multiple times.
                ids = tuple(
                    r[0]
                    for r in query(
                        """
                        SELECT id FROM messages
                        WHERE room = :r AND data IS NOT NULL AND id IN :ids
                        """,
                        r=self.id,
                        ids=tuple(message_ids[i : i + 50]),
                        bind_expanding=['ids'],
                    )
                )

                if ids:
                    if not self.check_moderator(deleter):
                        # If not a moderator then we only proceed if all of the messages are the
                        # user's own:
                        res = query(
                            """
                            SELECT EXISTS(
                                SELECT * FROM messages WHERE "user" != :u AND id IN :ids
                            )
                            """,
                            u=deleter.id,
                            ids=ids,
                            bind_expanding=['ids'],
                        )
                        if res.first()[0]:
                            raise BadPermission()

                    query(
                        "DELETE FROM message_details WHERE id IN :ids",
                        ids=ids,
                        bind_expanding=['ids'],
                    )

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
            app.logger.warning(
                f"Error deleting all posts by {poster} from {self} by {deleter}: {fail}"
            )
            raise BadPermission()

        with db.transaction():
            deleted = [
                r[0]
                for r in query(
                    'SELECT id FROM messages WHERE room = :r AND "user" = :u AND data IS NOT NULL',
                    room=self.id,
                    u=poster.id,
                )
            ]

            query(
                'DELETE FROM message_details WHERE room = :r AND "user" = :u',
                r=self.id,
                u=poster.id,
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
            result = query(
                f"""
                UPDATE files SET room = NULL, expiry = :now WHERE room = :r AND uploader = :u
                    {'AND id != :omit' if omit_id else ''}
                """,
                now=time.time(),
                r=self.id,
                u=poster.id,
                omit=omit_id,
            )
            files_removed = result.rowcount

        # FIXME: send `deleted` to mule

        app.logger.debug(
            f"Delete all posts by {poster} from {self}: {len(deleted)} posts, {files_removed} files"
        )

        return len(deleted), files_removed

    def attachments_size(self):
        """Returns the number and aggregate size of attachments currently stored in this room"""
        return query(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files WHERE room = :r", r=self.id
        ).first()[0:2]

    def get_mods(self, user=None):
        """
        Returns session_ids of visible moderators, visible admins, hidden moderators, and hidden
        admins that `user` is permitted to know about.  Hidden moderator and admins are only visible
        if `user` is an admin or moderator.

        Returns a 4-tuple of lists of session ids:
        ([public_mods], [public_admins], [hidden_mods], [hidden_admins])
        """

        m, hm, a, ha = [], [], [], []
        for session_id, visible, admin in query(
            """
            SELECT session_id, visible_mod, admin FROM user_permissions
            WHERE room = :r AND moderator
            ORDER BY session_id
            """,
            r=self.id,
        ):
            if session_id[0:2] == "ff" and session_id[2:] == crypto.server_pubkey_hex:
                # Skip the system user which isn't really a moderator/admin account
                continue

            ((a if admin else m) if visible else (ha if admin else hm)).append(session_id)

        if user is None or not any(user.session_id in modlist for modlist in (m, hm, a, ha)):
            hm, ha = [], []

        return m, a, hm, ha

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
        for session_id, visible, admin in query(
            """
            SELECT session_id, o.visible_mod, o.admin
            FROM user_permission_overrides o JOIN users ON o."user" = users.id
            WHERE room = :r AND o.moderator
            ORDER BY session_id
            """,
            r=self.id,
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
            app.logger.warning(
                f"Unable to set {user} as {'admin' if admin else 'moderator'} of {self}: "
                f"{added_by} is not an admin"
            )
            raise BadPermission()

        query(
            """
            INSERT INTO user_permission_overrides (room, "user", moderator, admin, visible_mod)
            VALUES (:r, :u, TRUE, :admin, :visible)
            ON CONFLICT (room, "user") DO UPDATE SET
                moderator = excluded.moderator,
                admin = excluded.admin,
                visible_mod = excluded.visible_mod
            """,
            r=self.id,
            u=user.id,
            admin=admin,
            visible=visible,
        )

        if user.id in self._perm_cache:
            del self._perm_cache[user.id]

        app.logger.info(f"{added_by} set {user} as {'admin' if admin else 'moderator'} of {self}")

    def remove_moderator(self, user: User, *, removed_by: User):
        """Remove `user` as a moderator/admin of this room.  Requires admin permission."""

        if not self.check_admin(removed_by):
            raise BadPermission()

        query(
            """
            UPDATE user_permission_overrides
            SET moderator = FALSE, admin = FALSE, visible_mod = TRUE
            WHERE room = :r AND "user" = :u
            """,
            r=self.id,
            u=user.id,
        )

        if user.id in self._perm_cache:
            del self._perm_cache[user.id]

        app.logger.info(f"{removed_by} removed {user} as mod/admin of {self}")

    def ban_user(self, to_ban: User, *, mod: User, timeout: Optional[float] = None):
        """
        Adds a ban to this room of `to_ban`, banned by `mod`, with the ban lasting for `timeout`
        seconds (or forever, if timeout is omitted or None).

        Raises BadPermission is the given `mod` is lacking the required permission to institute the
        ban (i.e. not-a-moderator, or not-an-admin if trying to ban a room moderator/admin, or
        trying to ban a global mod/admin from a room).

        Note that 0 (or negative) is accepted for timeout, which *does* ban the user, but the ban
        will be reverted within a few seconds (at the next database cleanup iteration); this is
        primarily provided for testing.
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
            app.logger.warning(f"Error banning {to_ban} from {self} by {mod}: {fail}")
            raise BadPermission()

        # TODO: log the banning action for auditing

        with db.transaction():
            query(
                """
                INSERT INTO user_permission_overrides (room, "user", banned, moderator, admin)
                    VALUES (:r, :ban, TRUE, FALSE, FALSE)
                ON CONFLICT (room, user) DO
                    UPDATE SET banned = TRUE, moderator = FALSE, admin = FALSE
                """,
                r=self.id,
                ban=to_ban.id,
            )

            if timeout:
                query(
                    """
                    INSERT INTO user_permission_futures (room, "user", at, banned)
                        VALUES (:r, :banned, :at, FALSE)
                    """,
                    r=self.id,
                    banned=to_ban.id,
                    at=time.time() + timeout,
                )

        if to_ban.id in self._perm_cache:
            del self._perm_cache[to_ban.id]

        app.logger.debug(f"Banned {to_ban} from {self} (banned by {mod})")

    def unban_user(self, to_unban: User, *, mod: User):
        """
        Removes a user ban from a user, if present.  `mod` must be a moderator.

        Returns true if a ban was removed, false if the user wasn't banned.

        Throws on other errors (e.g. permission denied).
        """

        if not self.check_moderator(mod):
            app.logger.warning(f"Error unbanning {to_unban} from {self} by {mod}: not a moderator")
            raise BadPermission()

        result = query(
            """
            UPDATE user_permission_overrides SET banned = FALSE
            WHERE room = :r AND "user" = :unban AND banned
            """,
            r=self.id,
            unban=to_unban.id,
        )
        if result.rowcount > 0:
            app.logger.debug(f"{mod} unbanned {to_unban} from {self}")

            if to_unban.id in self._perm_cache:
                del self._perm_cache[to_unban.id]

            return True

        app.logger.debug(f"{mod} unbanned {to_unban} from {self} (but user was already unbanned)")
        return False

    def get_bans(self):
        """
        Retrieves all the session IDs banned from this room.  This does not check permissions: i.e.
        it should only be accessed by moderators/admins.
        """

        return sorted(
            r[0]
            for r in query(
                "SELECT session_id FROM user_permissions WHERE room = :r AND banned", r=self.id
            )
        )

    def set_permissions(self, user: User, *, mod: User, **perms):
        """
        Grants or removes read, write, and/or upload permissions to the given user in this room.
        `mod` must have moderator access in the room.

        Permitted keyword args are: read, write, upload.  Each can be set to True, False, or None to
        apply an explicit grant, explicit revocation, or return to room defaults, respectively.
        (That is, None removes the override, if currently present, so that the user permission will
        use the room default; the others set this user's permission to allowed/disallowed).

        If a permission key is omitted then it will not be changed at all if it already exists, and
        will be NULL if a new permission row is being created.
        """

        perm_types = ('read', 'write', 'upload')

        if any(k not in perm_types for k in perms.keys()):
            raise ValueError(f"Room.set_permissions: only {', '.join(perm_types)} may be specified")

        if not perms:
            raise ValueError(
                "Room.set_permissions: at least one of {', '.join(perm_types)} must be specified"
            )

        if not self.check_moderator(mod):
            app.logger.warning(f"Error set perms {perms} on {user} by {mod}: not a moderator")
            raise BadPermission()

        with db.transaction():
            set_perms = perms.keys()
            query(
                f"""
                INSERT INTO user_permission_overrides (room, "user", {', '.join(set_perms)})
                VALUES (:r, :u, :{', :'.join(set_perms)})
                ON CONFLICT (room, "user") DO UPDATE SET
                    {', '.join(f"{p} = :{p}" for p in set_perms)}
                """,
                r=self.id,
                u=user.id,
                read=perms.get('read'),
                write=perms.get('write'),
                upload=perms.get('upload'),
            )

        if user.id in self._perm_cache:
            del self._perm_cache[user.id]

        app.logger.debug(f"{mod} applied {self} permission(s) {perms} to {user}")

    def get_file(self, file_id: int):
        """Retrieves a file uploaded to this room by id.  Returns None if not found."""
        row = query("SELECT * FROM files WHERE room = :r AND id = :f", r=self.id, f=file_id).first()

        if not row and db.HAVE_FILE_ID_HACKS:
            row = query(
                """
                SELECT * FROM files WHERE id = (
                    SELECT file FROM file_id_hacks WHERE room = :r AND old_file_id = :old_fid
                )
                """,
                r=self.id,
                old_fid=file_id,
            ).first()

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
            with db.transaction():
                expiry = None if lifetime is None else time.time() + lifetime

                # Insert the file row first with path='tmp' then come back and update it to the
                # proper path, which we want to base on the resulting file id.
                file_id = db.insert_and_get_pk(
                    """
                    INSERT INTO files (room, uploader, size, expiry, filename, path)
                    VALUES (:r, :u, :size, :expiry, :filename, 'tmp')
                    """,
                    "id",
                    r=self.id,
                    u=uploader.id,
                    size=len(content),
                    expiry=expiry,
                    filename=filename,
                )

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

                query("UPDATE files SET path = :p WHERE id = :f", p=file_path, f=file_id)

                return file_id

        except Exception as e:
            app.logger.warning(f"Failed to write/update file {file_path}: {e}")
            if file_path is not None:
                try:
                    os.unlink(file_path)
                except Exception:
                    pass
            raise

    def pin(self, msg_id: int, admin: User):
        """
        Pins a message to this room.  Requires admin room permissions.

        Pinning a message that is already pinned will keep it pinned but update the
        pinned_by/pinned_at properties to the current admin/current time.  (This can be useful to
        reorder pins, which are always sorted oldest-to-newest).
        """

        if not self.check_admin(admin):
            app.logger.warning(f"Unable to pin message to {self}: {admin} is not an admin")
            raise BadPermission()

        with db.transaction():
            # Make sure the given messages actually exist in this room:
            if not query(
                """
                SELECT COUNT(*) FROM messages
                WHERE room = :r AND id = :m AND data IS NOT NULL
                    AND NOT filtered AND whisper IS NULL AND NOT whisper_mods
                """,
                r=self.id,
                m=msg_id,
            ).first()[0]:
                raise NoSuchPost(msg_id)

            query(
                """
                INSERT INTO pinned_messages (room, message, pinned_by) VALUES (:r, :m, :a)
                ON CONFLICT (room, message) DO UPDATE SET pinned_by = :a, pinned_at = :now
                """,
                r=self.id,
                m=msg_id,
                a=admin.id,
                now=time.time(),
            )
        self._pinned = None

    def unpin_all(self, admin: User):
        """
        Unpins all pinned messages from this room.  Requires admin privileges.  Returns the
        number of pinned messages removed.
        """

        if not self.check_admin(admin):
            app.logger.warning("Unable to unpin all messages from {self}: {admin} is not an admin")
            raise BadPermission()

        count = query("DELETE FROM pinned_messages WHERE room = :r", r=self.id).rowcount
        if count != 0:
            self._pinned = None
        return count

    def unpin(self, msg_id: int, admin: User):
        """
        Unpins a pinned message in this room.  Requires admin privileges.  Returns the number of
        pinned messages actually removed (i.e. 0 or 1).
        """

        if not self.check_admin(admin):
            app.logger.warning("Unable to unpin message from {self}: {admin} is not an admin")
            raise BadPermission()

        count = query(
            "DELETE FROM pinned_messages WHERE room = :r AND message = :m", r=self.id, m=msg_id
        ).rowcount
        if count != 0:
            self._pinned = None
        return count


def get_rooms():
    """Get a list of all rooms; does not check permissions."""
    return [Room(row) for row in query("SELECT * FROM rooms ORDER BY token")]


def get_readable_rooms(user: Optional[User] = None):
    """
    Get a list of rooms that a user can access; if user is None then return all publicly readable
    rooms.
    """
    if user is None:
        result = query("SELECT * FROM rooms WHERE read ORDER BY token")
    else:
        result = query(
            """
            SELECT rooms.* FROM user_permissions perm JOIN rooms ON rooms.id = room
            WHERE "user" = :u AND perm.read AND NOT perm.banned
            ORDER BY token
            """,
            u=user.id,
        )
    return [Room(row) for row in result]


def get_deletions_deprecated(room: Room, since):
    if since:
        result = query(
            """
            SELECT id, seqno FROM messages
            WHERE room = :r AND seqno > :since AND data IS NULL
            ORDER BY seqno ASC LIMIT 256
            """,
            r=room.id,
            since=since,
        )
    else:
        result = query(
            """
            SELECT id, seqno FROM messages
            WHERE room = :r AND data IS NULL
            ORDER BY seqno DESC LIMIT 256
            """,
            r=room.id,
        )
    return [{'deleted_message_id': row[0], 'id': row[1]} for row in result]
