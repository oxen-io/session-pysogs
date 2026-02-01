from .. import config, crypto, db, utils, session_pb2 as protobuf
from ..db import query
from ..hashing import blake2b
from ..omq import send_mule, synchronous_mule_request
from oxenc import bt_deserialize
from ..web import app
from .user import User
from .file import File
from .post import Post
from nacl.signing import SigningKey
from .exc import (
    NoSuchRoom,
    NoSuchFile,
    NoSuchPost,
    AlreadyExists,
    BadPermission,
    PostRejected,
    PostRateLimited,
    InvalidData,
)

import os
import random
import re
import sqlalchemy.exc
import time
from typing import Optional, Union, List

import sys

test_suite = False
if "pytest" in sys.modules:
    test_suite = True

# TODO: These really should be room properties, not random global constants (these
# are carried over from old SOGS).
rate_limit_size = 5
rate_limit_interval = 16.0


# Character ranges for different filters.  This is ordered because some are subsets of each other
# (e.g. persian is a subset of the arabic character range).
alphabet_filter_patterns = [
    (
        'persian',
        re.compile(
            r'[\u0621-\u0628\u062a-\u063a\u0641-\u0642\u0644-\u0648\u064e-\u0651\u0655'
            r'\u067e\u0686\u0698\u06a9\u06af\u06be\u06cc]'
        ),
    ),
    ('arabic', re.compile(r'[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufefe]')),
    ('cyrillic', re.compile(r'[\u0400-\u04ff]')),
]
filter_privkeys = {}


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
        active_users - count of the number of active users in the past
            config.ROOM_DEFAULT_ACTIVE_THRESHOLD seconds.
        default_read - True if default user permissions includes read permission
        default_accessible - True if default user permissions include accessible permission
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
            self.active_users,
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
                'active_users',
            )
        )
        self._default_read, self._default_accessible, self._default_write, self._default_upload = (
            bool(row[c]) for c in ('read', 'accessible', 'write', 'upload')
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

        with db.transaction():
            query(
                """
                DELETE FROM user_reactions WHERE reaction IN (
                    SELECT id FROM reactions WHERE message IN (
                        SELECT id FROM messages WHERE room = (
                            SELECT id FROM rooms WHERE token = :t)))
                """,
                t=self.token,
            )
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
        if name != self._name:
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
        if desc != self._description:
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

            if file.room_id != self.id:
                raise NoSuchFile(file.room_id)

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
    def default_accessible(self):
        """
        Returns True if this room has the publicly accessible (e.g. by a new user) permission set.
        Note that the the accessible permission only applies when `read` is false: if a user has
        read permission then they implicitly have accessibility permission even if this field is
        false.
        """
        return self._default_accessible

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

        if read != self._default_read:
            with db.transaction():
                query("UPDATE rooms SET read = :read WHERE id = :r", r=self.id, read=read)
                self._refresh(perms=True)

    @default_accessible.setter
    def default_accessible(self, accessible: bool):
        """Sets the default accessible permission of the room"""

        if accessible != self._default_accessible:
            with db.transaction():
                query(
                    "UPDATE rooms SET accessible = :accessible WHERE id = :r",
                    r=self.id,
                    accessible=accessible,
                )
                self._refresh(perms=True)

    @default_write.setter
    def default_write(self, write: bool):
        """Sets the default write permission of the room"""

        if write != self._default_write:
            with db.transaction():
                query("UPDATE rooms SET write = :write WHERE id = :r", r=self.id, write=write)
                self._refresh(perms=True)

    @default_upload.setter
    def default_upload(self, upload: bool):
        """Sets the default upload permission of the room"""

        if upload != self._default_upload:
            with db.transaction():
                query("UPDATE rooms SET upload = :upload WHERE id = :r", r=self.id, upload=upload)
                self._refresh(perms=True)

    def active_users_last(self, cutoff: float):
        """
        Queries the number of active users in the past `cutoff` seconds.  This is like the
        `active_users` property except that it always queries for the instantaneous value
        (`active_users` is only updated every few seconds in sogs.cleanup), and supports values
        other than the default activity threshold.

        Note that room activity records are periodically removed, so specifying a cutoff above
        config.ROOM_ACTIVE_PRUNE_THRESHOLD days is useless.
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
        accessible=False,
        write=False,
        upload=False,
        get_all=False,
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
        - accessible -- if true then the user must have accessible access; note that this permission
          is satisfied by *either* the `accessible` or `read` database flags (that is: read implies
          accessible).
        - write -- if true then the user must have write access
        - upload -- if true then the user must have upload access; this should usually be combined
          with write=True.

        You can specify multiple permissions as True, in which case all must be satisfied.  If you
        specify no permissions as required then the check only checks whether a user is banned but
        otherwise requires no specific permission.
        """

        if user is None:
            is_banned, can_read, can_access, can_write, can_upload, is_mod, is_admin = (
                False,
                bool(self.default_read),
                bool(self.default_accessible),
                bool(self.default_write),
                bool(self.default_upload),
                False,
                False,
            )
        else:
            if user.id not in self._perm_cache:
                row = query(
                    """
                    SELECT banned, read, accessible, write, upload, moderator, admin
                    FROM user_permissions
                    WHERE room = :r AND "user" = :u
                    """,
                    r=self.id,
                    u=user.id,
                ).first()
                self._perm_cache[user.id] = [bool(c) for c in row]

            (is_banned, can_read, can_access, can_write, can_upload, is_mod, is_admin) = (
                self._perm_cache[user.id]
            )

        if get_all:
            return {
                "is_banned": is_banned,
                "can_read": can_read,
                "can_access": can_access,
                "can_write": can_write,
                "can_upload": can_upload,
                "is_mod": is_mod,
                "is_admin": is_admin,
            }

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
            and (not accessible or can_access or can_read)
            and (not read or can_read)
            and (not write or can_write)
            and (not upload or can_upload)
        )

    # Shortcuts for check_permission calls

    def check_unbanned(self, user: Optional[User]):
        return self.check_permission(user)

    def check_read(self, user: Optional[User] = None):
        return self.check_permission(user, read=True)

    def check_accessible(self, user: Optional[User] = None):
        return self.check_permission(user, accessible=True)

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
        sequence: Optional[int] = None,
        after: Optional[int] = None,
        before: Optional[int] = None,
        recent: bool = False,
        single: Optional[int] = None,
        limit: int = 256,
        reactions: bool = True,
        reaction_updates: bool = True,
        reactor_limit: int = 0,
    ):
        """
        Returns up to `limit` message updates that `user` should see:
        - all non-deleted new room messages
        - newly edited messages
        - newly deleted messages
        - whispers directed to the user
        - whispers directed to moderators (only applicable if the user is a moderator)
        - reaction updates (if `reaction_updates` is true, and using `sequence`)

        Exactly one of `sequence`, `after`, `before`, `recent` or `single` must be specified:
        - `sequence=N` returns updates made since the given `seqno` (that is: the have seqno greater
          than N).  Messages and reactions are returned in sequence order.
        - `after=N` returns messages with ids greater than N in ascending order.  This is normally
          *not* what you want for fetching messages as it omits edits and deletions; typically you
          want to retrieve by seqno instead.
        - `before=N` returns messages with ids less than N in descending order
        - `recent=True` returns the most recent messages in descending order
        - `single=123` returns a singleton list containing the single message with the given message
          id, or an empty list if the message doesn't exist or isn't readable by the user.

        Other parameters:
        - `reactions` controls whether reaction details are added to retrieved messages.  Defaults
          to `True`.

        - `reaction_updates` controls whether the result returns reaction-only message update rows:
          these are dicts with only the id/seqno/reaction keys (rather than the full message
          details) and are returned for messages that have had reactions changes since the requested
          sequence value but are not otherwise changed.  Such reaction-only updates are returned
          only when sequence polling (i.e.  using the `sequence` argument).

          This field has no effect when `reactions` is false.

        - `reactor_limit` controls how many of the reactor list to return with reaction info; this
          is passed through to `get_reactions`.  This field has no effect when `reactions` is false.

        Note that data and signature are returned as bytes, *not* base64 encoded.  Session message
        padding *is* appended to the data field (i.e. this returns the full value, not the
        padding-trimmed value actually stored in the database).
        """

        mod = self.check_moderator(user)
        whispers_only = not self.check_read(
            user
        )  # access but not read still allows whispers to be seen

        # if this is a "public" read request and default read is false, return empty list
        if whispers_only and not user:
            return []

        # if user doesn't have permission overrides for this room, treat this as a permissions request
        if whispers_only and len(self.user_permissions(user)) == 0:
            req = {
                "user_id": user.id,
                "session_id": user.using_id,
                "room_id": self.id,
                "room_token": self.token,
            }
            # response is meaningless for now; just used to wait for mule.
            from datetime import timedelta

            bot_resp = synchronous_mule_request(
                "worker.request_read", req, prefix=None, timeout=timedelta(seconds=3)
            )

        msgs = []

        opt_count = sum(arg is not None for arg in (sequence, after, before, single)) + bool(recent)
        if opt_count == 0:
            raise RuntimeError(
                "Exactly one of sequence=, before=, after=, recent=, or single= is required"
            )
        if opt_count > 1:
            raise RuntimeError(
                "Cannot specify more than one of sequence=, before=, after=, recent=, single="
            )

        if sequence is None:
            reaction_updates = False

        if limit <= 0:
            limit = 256

        # Handle id mapping from an old database import in case the client is requesting
        # messages since some id from the old db.
        if after is not None and db.ROOM_IMPORT_HACKS and self.id in db.ROOM_IMPORT_HACKS:
            max_old_id, offset = db.ROOM_IMPORT_HACKS[self.id]
            if after <= max_old_id:
                after += offset

        # We include deletions only if doing a sequence update request, but only include deletions
        # for messages that were created *before* the given sequence number (the client won't have
        # messages created after that, so it is pointless to send them tombstones for messages they
        # don't know about).
        not_deleted_clause = (
            'AND (data IS NOT NULL OR seqno_creation <= :sequence)'
            if sequence is not None
            else 'AND data IS NOT NULL'
        )
        message_clause = (
            'AND seqno > :sequence AND seqno_data > :sequence'
            if sequence is not None and not reaction_updates
            else (
                'AND seqno > :sequence'
                if sequence is not None
                else (
                    'AND id > :after'
                    if after is not None
                    else (
                        'AND id < :before'
                        if before is not None
                        else 'AND id = :single' if single is not None else ''
                    )
                )
            )
        )

        whisper_clause = (
            # For a mod we want to see:
            # - all whisper_mods messsages
            # - anything directed to us specifically
            # - anything we sent (i.e. outbound whispers)
            # - non-whispers
            'AND (whisper_mods OR whisper = :user OR "user" = :user OR whisper IS NULL)'
            if mod
            # If the user only has access but not read/write, we want to see:
            # - anything with whisper_to sent to us
            else (
                "AND whisper = :user"
                if whispers_only
                # For a regular user we want to see:
                # - anything with whisper_to sent to us
                # - non-whispers
                else (
                    "AND (whisper = :user OR (whisper IS NULL AND NOT whisper_mods))"
                    if user
                    # Otherwise for public, non-user access we want to see:
                    # - non-whispers
                    else "AND whisper IS NULL AND NOT whisper_mods"
                )
            )
        )

        order_limit = (
            'ORDER BY seqno ASC LIMIT :limit'
            if sequence is not None
            else (
                ''
                if single is not None
                else (
                    'ORDER BY id ASC LIMIT :limit'
                    if after is not None
                    else 'ORDER BY id DESC LIMIT :limit'
                )
            )
        )
        for row in query(
            f"""
            SELECT * FROM message_details
            WHERE room = :r AND NOT filtered
                {not_deleted_clause}
                {message_clause}
                {whisper_clause}
            {order_limit}
            """,
            r=self.id,
            sequence=sequence,
            after=after,
            before=before,
            single=single,
            user=user.id if user else None,
            limit=limit,
        ):
            if sequence and row['seqno_reactions'] > sequence >= row['seqno_data']:
                # This is a reaction-only update, so we only want to include the reaction info
                # (added later) but not the full details.
                msgs.append({x: row[x] for x in ('id', 'seqno')})
                continue

            msg = {x: row[x] for x in ('id', 'posted', 'seqno')}
            msg["session_id"] = row["signing_id"]
            data = row['data']
            if data is None:
                msg['data'] = None
                msg['deleted'] = True
            else:
                msg['data'] = utils.add_session_message_padding(data, row['data_size'])
                msg['signature'] = row['signature']
            if row['edited'] is not None:
                msg['edited'] = row['edited']
            if row['whisper_to'] is not None or row['whisper_mods']:
                msg['whisper'] = True
                msg['whisper_mods'] = row['whisper_mods']
                if row['whisper_to'] is not None:
                    msg['whisper_to'] = row['whisper_to']
            msgs.append(msg)
        app.logger.debug(f"{len(msgs)} going to user for room")

        # If the user only has "access", we want to lie about sequence numbers so that if
        # that user gains "read" later their client will request messages from before that
        # access was granted.
        if whispers_only:
            for msg in msgs:
                msg['seqno'] = 0

        if reactions:
            reacts = self.get_reactions(
                # Fetch reactions for messages, but skip deleted messages (that have data set to an
                # explicit None) since we already know they don't have reactions.
                [x['id'] for x in msgs if 'data' not in x or x['data'] is not None],
                user,
                reactor_limit=reactor_limit,
                session_ids=True,
            )
            for msg in msgs:
                if 'data' not in msg or msg['data'] is not None:
                    msg['reactions'] = reacts.get(msg['id'], {})

        return msgs

    def filtering(self):
        settings = {
            'profanity_filter': config.PROFANITY_FILTER,
            'profanity_silent': config.PROFANITY_SILENT,
            'alphabet_filters': config.ALPHABET_FILTERS,
            'alphabet_silent': config.ALPHABET_SILENT,
        }
        if self.token in config.ROOM_OVERRIDES:
            for k in (
                'profanity_filter',
                'profanity_silent',
                'alphabet_filters',
                'alphabet_silent',
            ):
                if k in config.ROOM_OVERRIDES[self.token]:
                    settings[k] = config.ROOM_OVERRIDES[self.token][k]
        return settings

    def filter_should_reply(self, filter_type, filter_lang):
        """If the settings say we should reply to a filter, this returns a tuple of

        (profile name, message format, whisper)

        where profile name is the name we should use in the reply, message format is a string with
        substitutions ready, and whisper is True/False depending on whether it should be whispered
        to the user (True) or public (False).

        If we shouldn't reply this returns (None, None, None)
        """

        if not config.FILTER_SETTINGS:
            return (None, None, None)

        reply_format = None
        profile_name = 'SOGS'
        public = False

        # Precedences from least to most specific so that we load values from least specific first
        # then overwrite them if we find a value in a more specific section
        room_precedence = ('*', self.token)
        filter_precedence = ('*', filter_type, filter_lang) if filter_lang else ('*', filter_type)

        for r in room_precedence:
            s1 = config.FILTER_SETTINGS.get(r)
            if s1 is None:
                continue
            for f in filter_precedence:
                settings = s1.get(f)
                if settings is None:
                    continue

                rf = settings.get('reply')
                pn = settings.get('profile_name')
                pb = settings.get('public')
                if rf is not None:
                    reply_format = random.choice(rf)
                if pn is not None:
                    profile_name = pn
                if pb is not None:
                    public = pb

        return (reply_format, profile_name, public)

    def should_filter(self, user: User, data: bytes):
        """
        Checks a message for disallowed alphabets and profanity (if the profanity
        filter is enabled).

        - Returns None if this message passes (i.e. didn't trigger any filter, or is
          being posted by an admin to whom the filters don't apply).

        - Returns a callback if the message fails but should be silently accepted.  The callback
          should be called (with no arguments) *after* the filtered message is inserted into the db.

        - Throws PostRejected if the message should be rejected (and rejection passed back to the
          user).
        """
        msg_ = None

        def msg():
            nonlocal msg_
            if msg_ is None:
                msg_ = Post(raw=data)
            return msg_

        if not config.FILTER_MODS and self.check_moderator(user):
            return None

        filter_type = None
        filter_lang = None

        filt = self.filtering()
        alphabets = filt['alphabet_filters']
        for lang, pattern in alphabet_filter_patterns:
            if lang not in alphabets:
                continue

            if not pattern.search(msg().text):
                continue

            # Filter it!
            filter_type, filter_lang = 'alphabet', lang
            break

        if not filter_type and filt['profanity_filter']:
            import better_profanity

            for part in (msg().text, msg().username):
                if better_profanity.profanity.contains_profanity(part):
                    filter_type = 'profanity'
                    break

        if not filter_type:
            return None

        silent = filt[filter_type + '_silent']

        msg_fmt, prof_name, pub = self.filter_should_reply(filter_type, filter_lang)
        if msg_fmt:
            pbmsg = protobuf.Content()
            body = msg_fmt.format(
                profile_name=(user.using_id if msg().username is None else msg().username),
                profile_at="@" + user.using_id,
                room_name=self.name,
                room_token=self.token,
            ).encode()
            pbmsg.dataMessage.body = body
            pbmsg.dataMessage.timestamp = int(time.time() * 1000)
            pbmsg.dataMessage.profile.displayName = prof_name

            # Add two bytes padding so that session doesn't get confused by a lack of padding
            pbmsg = pbmsg.SerializeToString() + b'\x80\x00'

            # Make a fake signing key based on prof_name and the server privkey (so that different
            # names use different keys; otherwise the bot names overwrite each other in Session
            # clients when a later message has a new profile name).
            global filter_privkeys
            if prof_name in filter_privkeys:
                signingkey = filter_privkeys[prof_name]
            else:
                signingkey = SigningKey(
                    blake2b(
                        prof_name.encode() + crypto.server_signkey.encode(), key=b'sogsfiltering'
                    )
                )
                filter_privkeys[prof_name] = signingkey

            sig = signingkey.sign(pbmsg).signature
            server_fake_user = User(
                session_id='15' + signingkey.verify_key.encode().hex(), autovivify=True, touch=False
            )

            def insert_reply():
                query(
                    """
                    INSERT INTO messages
                        (room, "user", data, data_size, signature, whisper, alt_id)
                        VALUES
                        (:r, :u, :data, :data_size, :signature, :whisper, :alt_id)
                    """,
                    r=self.id,
                    u=server_fake_user.id,
                    data=pbmsg[:-2],
                    data_size=len(pbmsg),
                    signature=sig,
                    whisper=None if pub else user.id,
                    alt_id=server_fake_user.using_id if server_fake_user.alt_id else None,
                )

            if filt[filter_type + '_silent']:
                # Defer the insertion until after the filtered row gets inserted
                return insert_reply
            else:
                insert_reply()

        elif silent:
            # No reply, so just return an empty callback
            def noop():
                pass

            return noop

        # FIXME: can we send back some error code that makes Session not retry?
        raise PostRejected(f"filtration rejected message ({filter_type})")

    def _own_files(self, msg_id: int, files: List[int], user):
        """
        Associated any of the given file ids with the given message id.  Only files that are recent,
        expiring, unowned uploads by the same user are actually updated.
        """
        expiry = None
        if config.UPLOAD_DEFAULT_EXPIRY:
            expiry = time.time() + config.UPLOAD_DEFAULT_EXPIRY

        return db.query(
            """
            UPDATE files SET
                message = :m,
                expiry = :exp
            WHERE id IN :ids
                AND room = :r
                AND uploader = :u
                AND message IS NULL
                AND uploaded >= :recent
                AND expiry IS NOT NULL
            """,
            m=msg_id,
            exp=expiry,
            ids=files,
            r=self.id,
            u=user.id,
            recent=time.time() - 3600,
            bind_expanding=['ids'],
        )

    def insert_message(self, message):
        with db.transaction():

            unpadded_data = utils.remove_session_message_padding(message[b"message_data"])
            msg_id = db.insert_and_get_pk(
                """
                INSERT INTO messages
                    (room, "user", data, data_size, signature, filtered, whisper, whisper_mods, alt_id)
                    VALUES
                    (:r, :u, :data, :data_size, :signature, :filtered, :whisper, :whisper_mods, :alt_id)
                """,
                "id",
                r=self.id,
                u=message[b"user_id"],
                data=unpadded_data,
                data_size=message[b"data_size"],
                signature=message[b"sig"],
                filtered=message[b"filtered"],
                whisper=message[b"whisper_to"] if b"whisper_to" in message else None,
                whisper_mods=message[b"whisper_mods"],
                alt_id=message[b"alt_id"] if b"alt_id" in message else None,
            )
            return msg_id

    def bot_handle_message(self, message_args):
        try:
            app.logger.warning("Filtering via bots")

            return bt_deserialize(
                synchronous_mule_request("worker.message_request", message_args, prefix=None)[0]
            )
        except Exception as e:
            app.logger.warn(f"Bot filter exception: {e}")
            if not test_suite:
                raise PostRejected(f"filtration rejected message (bot rejected)")

    def add_post(
        self,
        user: User,
        data: bytes,
        sig: bytes,
        *,
        whisper_to: Optional[Union[User, str]] = None,
        whisper_mods: bool = False,
        files: List[int] = [],
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

        if data is None or sig is None or len(sig) != 64:
            raise InvalidData()

        whisper_mods = bool(whisper_mods)
        if (whisper_to or whisper_mods) and not self.check_moderator(user):
            app.logger.warning(f"Cannot post a whisper to {self}: {user} is not a moderator")
            raise BadPermission()

        if whisper_to and not isinstance(whisper_to, User):
            whisper_to = User(session_id=whisper_to, autovivify=True, touch=False)

        filtered = None  # self.should_filter(user, data)
        if config.USE_OLD_SOGS_FILTERING:
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

        message_args = {
            "room_id": self.id,
            "room_token": self.token,
            "room_name": self.name,
            "user_id": user.id,
            "session_id": user.session_id,
            "message_data": data,
            "data_size": data_size,
            "sig": sig,
            "filtered": filtered is not None,
            "is_mod": self.check_moderator(user),
            "whisper_mods": whisper_mods,
        }
        if whisper_to:
            message_args["whisper_to"] = whisper_to.id
        if user.alt_id:
            message_args["alt_id"] = user.using_id

        bot_response = self.bot_handle_message(message_args)

        if not b"ok" in bot_response:
            error_str = (
                bot_response[b"error"] if b"error" in bot_response else "an unknown error occurred"
            )
            app.logger.warning(f"add_post, bot error: {error_str}")
            raise PostRejected(f"{error_str}")

        if b"msg_id" not in bot_response:
            # TODO: work out a response Session will like that says "message handled fine, but not inserted"
            #       e.g. for slash-command handling
            return dict()

        msg_id = bot_response[b"msg_id"]

        with db.transaction():

            if files:
                # Take ownership of any uploaded files attached to the post:
                self._own_files(msg_id, files, user)

            assert msg_id is not None
            row = query("SELECT posted, seqno FROM messages WHERE id = :m", m=msg_id).first()
            msg = {
                'id': msg_id,
                'session_id': user.using_id,
                'posted': row[0],
                'seqno': row[1],
                'data': data,
                'signature': sig,
                'reactions': {},
                'filtered': False,
            }
            if whisper_to or whisper_mods:
                msg['whisper'] = True
                msg['whisper_mods'] = whisper_mods
                if whisper_to:
                    msg['whisper_to'] = whisper_to.using_id

        # Don't call this inside the transaction because, if it's inserting a reply, we want the
        # reply to have a later timestamp for proper ordering (because the timestamp inside a
        # transaction is the time when the transaction started).
        if filtered is not None:
            filtered()

        return msg

    def edit_post(self, user: User, msg_id: int, data: bytes, sig: bytes, *, files: List[int] = []):
        """
        Edits a post in the room.  The post must exist, must have been authored by the same user,
        and must not be deleted.  The user must *currently* have write permission (i.e. if they lose
        write permission they cannot edit existing posts made before they were restricted).

        Edits cannot alter the whisper_to/whisper_mods properties.

        Raises:
        - BadPermission() if attempting to edit another user's message or not having write
          permission in the room.
        - A subclass of PostRejected() if the edit is unacceptable, for instance for triggering the
          profanity filter.
        - NoSuchPost() if the post is deleted.
        """
        if not self.check_write(user):
            raise BadPermission()

        if data is None or sig is None or len(sig) != 64:
            raise InvalidData()

        filtered = self.should_filter(user, data)
        with db.transaction():
            author = query(
                '''
                SELECT "user" FROM messages
                WHERE id = :m AND room = :r AND data IS NOT NULL
                ''',
                m=msg_id,
                r=self.id,
            ).first()
            if author is None:
                raise NoSuchPost()
            author = author[0]
            if author != user.id:
                raise BadPermission()

            if filtered is not None:
                # Silent filtering is enabled and the edit failed the filter, so we want to drop the
                # actual post update.
                filtered()
                return

            data_size = len(data)
            unpadded_data = utils.remove_session_message_padding(data)

            query(
                """
                UPDATE messages SET
                    data = :data, data_size = :data_size, signature = :sig WHERE id = :m
                """,
                m=msg_id,
                data=unpadded_data,
                data_size=data_size,
                sig=sig,
            )

            if files:
                # If the edit includes new attachments then own them:
                self._own_files(msg_id, files, user)

        send_mule("message_edited", msg_id)

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
                    r=self.id,
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
            omit_id = image.id if image and image.uploader == poster.id else None

            # TODO: Eventually we can drop this: once uploads have to be properly associated with
            # posts then the post deletion should trigger automatic expiry of post attachments.

            # Don't actually delete right now but just expire them so that the next db cleanup will
            # perform the deletion (and since they are expired, they won't be accessible in the
            # meantime).
            result = query(
                f"""
                UPDATE files SET expiry = 0.0 WHERE room = :r AND uploader = :u
                    {'AND id != :omit' if omit_id else ''}
                """,
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

    def reactions_counts(self):
        """Returns a list of [reaction, count] pairs where count is the aggregate count of that
        reaction use in this room"""
        return [
            (r, c)
            for r, c in query(
                """
                SELECT reaction, COUNT(*)
                FROM message_reactions JOIN messages ON messages.id = message
                WHERE room = :r
                GROUP BY reaction
                """,
                r=self.id,
            )
        ]

    def get_reactions(
        self,
        message_ids: List[int],
        user: Optional[User] = None,
        *,
        reactor_limit: int = 0,
        session_ids: bool = True,
    ):
        """
        Returns reaction information for the given messages.  Returns a dict of message id ->
        reaction info for any messages in the given list that have reactions.  The reaction info is
        itself a dict where keys are reaction strings and values are a dict containing keys:

        - `"count"` -- the total number of this reaction
        - `"you"` -- boolean set to true if `user` is given and the user has applied this reaction;
          omitted otherwise.
        - `"reactors"` -- if the input parameter `reactor_limit` is greater than 0 then this is a
          list of the session ids (if `session_ids`) or user ids (`session_ids` false) of the first
          `reactor_limit` users that applied this reaction.  Omitted if `reactor_limit` is 0.

        This method does *not* check for read access of the given messages: this is designed for
        internal use from message ids that have already been permission checked.
        """

        reacts = {}  # {msgid => {"🍍": {reactioninfo...}, ...}}, to get returned
        react_vals = {}  # {id => {reactioninfo...}, ...}, references to the above
        select_you = (
            'EXISTS(SELECT * FROM user_reactions WHERE reaction = r.id AND "user" = :uid) AS you'
            if user is not None
            else 'FALSE AS you'
        )
        for reactid, msgid, react, count, you in query(
            f"""
            SELECT
                id,
                message,
                reaction,
                (SELECT COUNT(*) FROM user_reactions WHERE reaction = r.id) AS react_count,
                {select_you}
            FROM reactions r
            WHERE message IN :msgs
            ORDER BY id
            """,
            bind_expanding=('msgs',),
            msgs=message_ids,
            uid=None if user is None else user.id,
        ):
            val = {"count": count}
            if you:
                val["you"] = True
            msg_reacts = reacts.setdefault(msgid, {})
            # We order by id to get insertion order, but we don't want to expose ids externally, so
            # use a simple counter here:
            val["index"] = len(msg_reacts)

            msg_reacts[react] = val
            if reactor_limit > 0:
                react_vals[reactid] = val

        if reacts and reactor_limit > 0:
            select_reactors = (
                (
                    """
                    SELECT reaction, session_id
                    FROM first_reactors JOIN users ON first_reactors."user" = users.id
                    """
                    if session_ids
                    else 'SELECT reaction, "user" FROM first_reactors '
                )
                + "WHERE reaction IN :reactids AND _order <= :max_order ORDER BY at"
            )
            for reactid, u in query(
                select_reactors,
                bind_expanding=['reactids'],
                reactids=list(react_vals.keys()),
                max_order=reactor_limit,
            ):
                react_vals[reactid].setdefault("reactors", []).append(u)

        return reacts

    def _check_reaction_request(
        self, user, msg_id, reaction, *, user_required=True, mod_required=False, allow_none=False
    ):
        if reaction is None:
            if not allow_none:
                app.logger.warning("No reaction provided")
                raise InvalidData()
        elif not isinstance(reaction, str) or not 1 <= len(reaction) <= 12:
            app.logger.warning(f"Invalid reaction string '{reaction}'")
            raise InvalidData()

        if user_required and not user:
            app.logger.warning("Reaction request requires user authentication")
            raise BadPermission()
        if mod_required and not self.check_moderator(user):
            app.logger.warning("Reaction request requires moderator authentication")
            raise BadPermission()

        if not self.is_regular_message(msg_id):
            raise NoSuchPost(msg_id)

        # users with "access" but not "read" can only react to whispers directed at them
        if not self.check_read(user):
            whisper_for_user = query(
                "SELECT count(*) FROM messages WHERE id = :msg and whisper = :user",
                msg=msg_id,
                user=user.id,
            ).first()[0]
            if not whisper_for_user:
                raise NoSuchPost(msg_id)

    def add_reaction(self, user: User, msg_id: int, reaction: str, *args, send_to_bots=True):
        """
        Adds a reaction to the given post.  Returns True if the reaction was added, False if the
        reaction by this user was already present, throws on other errors.

        SOGS requires that reactions be from 1 to 12 unicode characters long (throws InvalidData()
        if not satisfied).

        The post must exist in the room (throws NoSuchPost if it does not).

        The user must have read permission in the room (throws BadPermission if not).

        Returns a tuple of: bool indicating whether adding was successful (False = reaction already
        present), and the new message seqno value.
        """

        self._check_reaction_request(user, msg_id, reaction)

        with db.transaction():
            try:
                query(
                    """
                    INSERT INTO message_reactions (message, reaction, "user")
                    VALUES (:msg, :react, :user)
                    """,
                    msg=msg_id,
                    react=reaction,
                    user=user.id,
                )
                added = True
                seqno = query("SELECT seqno FROM messages WHERE id = :msg", msg=msg_id).first()[0]
                is_mod = self.check_moderator(user)
                is_admin = self.check_admin(user)
                if send_to_bots:
                    reaction_dict = {
                        'msg_id': msg_id,
                        'reaction': reaction,
                        'user_id': user.id,
                        'session_id': user.using_id,
                        'room_id': self.id,
                        'room_token': self.token,
                        'is_mod': is_mod,
                        'is_admin': is_admin,
                    }
                    send_mule("reaction_posted", reaction_dict)

            except sqlalchemy.exc.IntegrityError:
                added = False

        if not added:
            seqno = query("SELECT seqno FROM messages WHERE id = :msg", msg=msg_id).first()[0]

        return added, seqno

    def delete_reaction(self, user: User, msg_id: int, reaction: str):
        """
        Removes a reaction from the given post.  Returns True if the reaction was removed, False if
        the reaction was not present, throws on other errors.

        The requirements (and thrown exceptions) are the same as add_reaction.
        """

        self._check_reaction_request(user, msg_id, reaction)
        with db.transaction():
            removed = (
                query(
                    """
                    DELETE FROM user_reactions
                    WHERE reaction = (SELECT id FROM reactions WHERE message = :m AND reaction = :r)
                        AND "user" = :u
                    """,
                    m=msg_id,
                    r=reaction,
                    u=user.id,
                ).rowcount
                > 0
            )
            seqno = query("SELECT seqno FROM messages WHERE id = :msg", msg=msg_id).first()[0]

        return removed, seqno

    def delete_all_reactions(self, mod: User, msg_id: int, reaction: Optional[str] = None):
        """
        Removes all reactions from a post.  Supports removing all of a single reaction, or all
        reactions of any time.

        The caller must have moderator permissions in the room.

        Params:
        mod - the moderator performing the removal
        msg_id - the post id from which reactions are to be removed
        reaction - optional reaction string to remove.  If None, remove all reactions from the post.

        The reaction, if given, must be between 1 and 8 unicode characters.  The post must be a
        regular message (i.e. not a whisper, not deleted).

        Returns the total number of deleted reactions.
        """

        self._check_reaction_request(mod, msg_id, reaction, allow_none=True, mod_required=True)

        with db.transaction():
            removed = query(
                f"""
                DELETE FROM user_reactions WHERE
                    reaction IN (SELECT id FROM reactions WHERE
                        message = :m
                        {'AND reaction = :r' if reaction is not None else ''})
                """,
                m=msg_id,
                r=reaction,
            ).rowcount
            seqno = query("SELECT seqno FROM messages WHERE id = :msg", msg=msg_id).first()[0]

        return removed, seqno

    def get_reactors(
        self,
        message_id: int,
        reaction: str,
        user: Optional[User] = None,
        *,
        session_ids: bool = True,
        limit: Optional[int] = None,
    ):
        """
        Returns all of the reactors for a single reaction of a single message.  Returns a list of
        pairs containing the user (session id (if `session_ids`) or user id (if `not session_ids`))
        as first element and unix timestamp when reacted as second element.

        The returned ids are ordered by reaction time (oldest to most recent).
        """

        self._check_reaction_request(user, message_id, reaction, user_required=False)

        users = []
        for user, at in query(
            (
                'SELECT session_id, at FROM message_reactions r JOIN users ON r.user = users.id'
                if session_ids
                else 'SELECT "user", at FROM message_reactions r'
            )
            + " WHERE r.message = :msg AND r.reaction = :reaction ORDER BY at"
            + (" LIMIT :limit" if limit is not None and limit > 0 else ''),
            msg=message_id,
            reaction=reaction,
            limit=limit,
        ):
            users.append((user, at))

        return users

    def get_mods(self, user=None):
        """
        Returns session_ids of visible moderators, visible admins, hidden moderators, and hidden
        admins that `user` is permitted to know about.  Hidden moderator and admins are only visible
        if `user` is an admin or moderator.

        Returns a 4-tuple of lists of session ids:
        ([public_mods], [public_admins], [hidden_mods], [hidden_admins])
        """

        visible_clause = "" if self.check_moderator(user) else "AND visible_mod"
        m, hm, a, ha = [], [], [], []
        for session_id, visible, admin in query(
            f"""
            SELECT session_id, visible_mod, admin FROM room_moderators
            WHERE room = :r {visible_clause}
            ORDER BY session_id
            """,
            r=self.id,
        ):
            if session_id[0:2] == "ff" and session_id[2:] == crypto.server_pubkey_hex:
                # Skip the system user which isn't really a moderator/admin account
                continue

            ((a if admin else m) if visible else (ha if admin else hm)).append(session_id)

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

        `admin` can be specified as None to not touch the current admin permission on the room.

        added_by is the user performing the update and must have admin permission.
        """

        if not self.check_admin(added_by):
            app.logger.warning(
                f"Unable to set {user} as {'admin' if admin else 'moderator'} of {self}: "
                f"{added_by} is not an admin"
            )
            raise BadPermission()

        with db.transaction():
            query(
                f"""
                INSERT INTO user_permission_overrides
                    (room,
                    "user",
                    moderator,
                    {'admin,' if admin is not None else ''}
                    visible_mod)
                VALUES (:r, :u, TRUE, {':admin,' if admin is not None else ''} :visible)
                ON CONFLICT (room, "user") DO UPDATE SET
                    moderator = excluded.moderator,
                    {'admin = excluded.admin,' if admin is not None else ''}
                    visible_mod = excluded.visible_mod
                """,
                r=self.id,
                u=user.id,
                admin=admin,
                visible=visible,
            )

            self._refresh()
            if user.id in self._perm_cache:
                del self._perm_cache[user.id]

            app.logger.info(
                f"{added_by} set {user} as {'admin' if admin else 'moderator'} of {self}"
            )

    def remove_moderator(self, user: User, *, removed_by: User, remove_admin_only: bool = False):
        """
        Remove `user` as a moderator/admin of this room.  Requires admin permission.

        If `remove_admin_only` is True then user will have admin permissions removed but will remain
        a room moderator if already a room moderator or admin.
        """

        if not self.check_admin(removed_by):
            raise BadPermission()

        with db.transaction():
            query(
                f"""
                UPDATE user_permission_overrides
                SET admin = FALSE
                    {', moderator = FALSE, visible_mod = TRUE' if not remove_admin_only else ''}
                WHERE room = :r AND "user" = :u
                """,
                r=self.id,
                u=user.id,
            )

            self._refresh()
            if user.id in self._perm_cache:
                del self._perm_cache[user.id]

            app.logger.info(f"{removed_by} removed {user} ({user.using_id}) as mod/admin of {self}")

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

        with db.transaction():
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

            query(
                """
                INSERT INTO user_permission_overrides (room, "user", banned, moderator, admin)
                    VALUES (:r, :ban, TRUE, FALSE, FALSE)
                ON CONFLICT (room, "user") DO
                    UPDATE SET banned = TRUE, moderator = FALSE, admin = FALSE
                """,
                r=self.id,
                ban=to_ban.id,
            )

            # Replace (or remove) an existing scheduled bans/unbans:
            query(
                'DELETE FROM user_ban_futures WHERE room = :r AND "user" = :u',
                r=self.id,
                u=to_ban.id,
            )
            if timeout:
                query(
                    """
                    INSERT INTO user_ban_futures
                    (room, "user", banned, at) VALUES (:r, :u, FALSE, :at)
                    """,
                    r=self.id,
                    u=to_ban.id,
                    at=time.time() + timeout,
                )

            if to_ban.id in self._perm_cache:
                del self._perm_cache[to_ban.id]

            app.logger.debug(
                f"Banned {to_ban} from {self} {f'for {timeout}s ' if timeout else ''}"
                f"(banned by {mod})"
            )

    def unban_user(self, to_unban: User, *, mod: User):
        """
        Removes a user ban from a user, if present.  `mod` must be a moderator.

        Returns true if a ban was removed, false if the user wasn't banned.

        Throws on other errors (e.g. permission denied).
        """

        if not self.check_moderator(mod):
            app.logger.warning(f"Error unbanning {to_unban} from {self} by {mod}: not a moderator")
            raise BadPermission()

        with db.transaction():
            result = query(
                """
                UPDATE user_permission_overrides SET banned = FALSE
                WHERE room = :r AND "user" = :unban AND banned
                """,
                r=self.id,
                unban=to_unban.id,
            )
            if result.rowcount > 0:
                app.logger.warning(f"{mod} unbanned {to_unban} from {self}")

                if to_unban.id in self._perm_cache:
                    del self._perm_cache[to_unban.id]

                return True

            app.logger.warning(
                f"{mod} unbanned {to_unban} from {self} (but user was already unbanned)"
            )
            return False

    def get_bans(self):
        """
        Retrieves all the session IDs specifically banned from this room (not including global
        bans).  This does not check permissions: i.e.  it should only be accessed by
        moderators/admins.
        """

        return sorted(
            r[0]
            for r in query(
                """
                SELECT session_id
                FROM user_permission_overrides upo JOIN users ON upo."user" = users.id
                WHERE room = :r AND upo.banned
                """,
                r=self.id,
            )
        )

    def set_permissions(self, user: User, *, mod: User, **perms):
        """
        Grants or removes read, accessible, write, and/or upload permissions to the given user in
        this room.  `mod` must have moderator access in the room.

        Permitted keyword args are: read, accessible, write, upload.  Each can be set to True,
        False, or None to apply an explicit grant, explicit revocation, or return to room defaults,
        respectively.  (That is, None removes the override, if currently present, so that the user
        permission will use the room default; the others set this user's permission to
        allowed/disallowed).

        If a permission key is omitted then it will not be changed at all if it already exists, and
        will be NULL if a new permission row is being created.
        """

        perm_types = ('read', 'accessible', 'write', 'upload')

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
                accessible=perms.get('accessible'),
                write=perms.get('write'),
                upload=perms.get('upload'),
            )

            if user.id in self._perm_cache:
                del self._perm_cache[user.id]

            app.logger.debug(f"{mod} applied {self} permission(s) {perms} to {user}")

    def clear_future_permissions(
        self,
        user: User,
        *,
        mod: User,
        read: bool = False,
        write: bool = False,
        upload: bool = False,
    ):
        """
        Clears any scheduled room permissions changes for this user that change the read and/or
        write and/or upload permissions.

        This only removes the requested permission flags; for instance, if called with `read=True,
        write=True` and a future permission is scheduled that sets `read=true, write=false,
        upload=true` then the upload=true scheduled override will remain and the read/write
        scheduled changes will be removed.

        Also note that this removes *all* scheduled changes if there are multiple scheduled changes.
        """

        sets = []
        if read:
            sets.append("read = NULL")
        if write:
            sets.append("write = NULL")
        if upload:
            sets.append("upload = NULL")

        if not sets:
            return

        with db.transaction():
            r = query(
                f"""
                UPDATE user_permission_futures
                SET {', '.join(sets)}
                WHERE room = :r AND "user" = :u
                """,
                r=self.id,
                u=user.id,
            )

            # Clear any rows that we updated to all-nulls:
            if r.rowcount > 0:
                query(
                    """
                    DELETE FROM user_permission_futures
                    WHERE room = :r AND "user" = :u AND
                        read = NULL AND write = NULL AND upload = NULL
                    """,
                    r=self.id,
                    u=user.id,
                )

    def add_future_permission(
        self,
        user,
        *,
        at: float,
        mod: User,
        read: Optional[bool] = None,
        write: Optional[bool] = None,
        upload: Optional[bool] = None,
    ):
        """
        Schedules a future permission change for the given user in this room.

        The permission change will occur at (or within a few seconds of) the unix timestamp given in
        `at`, and will set read, write, and/or upload to the given boolean values.  (None values are
        left unchanged).
        """

        if not any(x is not None for x in (read, write, upload)):
            return

        with db.transaction():
            query(
                """
                INSERT INTO user_permission_futures (room, "user", at, read, write, upload)
                VALUES (:r, :u, :at, :read, :write, :upload)
                """,
                r=self.id,
                u=user.id,
                at=at,
                read=read,
                write=write,
                upload=upload,
            )

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
        if not row:
            return
        if row['expiry'] is None or row['expiry'] > time.time():
            return File(row)

    def upload_file(
        self,
        content: bytes,
        uploader: User,
        *,
        filename: Optional[str] = None,
        lifetime: Optional[float] = config.UPLOAD_DEFAULT_EXPIRY,
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

        files_dir = os.path.join(config.UPLOAD_PATH, self.token)
        os.makedirs(files_dir, exist_ok=True)

        if filename is None:
            upload_filename = None
        else:
            # nulls and / are prohibited characters on pretty much any system, so substitute them
            # out for a REPLACEMENT CHARACTER (U+FFFD) if in the given filename.
            filename = filename.replace('\0', '\uFFFD').replace('/', '\uFFFD')

            # For the actual filename we write to disk we heavily sanitize:
            upload_filename = re.sub(config.UPLOAD_FILENAME_BAD, "_", filename)

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

                if upload_filename is None:
                    upload_filename = '(unnamed)'

                if len(upload_filename) > config.UPLOAD_FILENAME_MAX:
                    upload_filename = (
                        upload_filename[: config.UPLOAD_FILENAME_KEEP_PREFIX]
                        + "..."
                        + upload_filename[-config.UPLOAD_FILENAME_KEEP_SUFFIX :]
                    )

                file_path = f"{files_dir}/{file_id}_{upload_filename}"

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

    def is_regular_message(self, msg_id: int):
        """
        Returns true if the given id is a regular (i.e. not deleted, not a mod whisper) message of this
        room.
        """
        return query(
            """
            SELECT COUNT(*) FROM messages
            WHERE room = :r AND id = :m AND data IS NOT NULL
                AND NOT filtered AND NOT whisper_mods
            """,
            r=self.id,
            m=msg_id,
        ).first()[0]

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
            if not self.is_regular_message(msg_id):
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
            self._refresh()

    def unpin_all(self, admin: User):
        """
        Unpins all pinned messages from this room.  Requires admin privileges.  Returns the
        number of pinned messages removed.
        """

        if not self.check_admin(admin):
            app.logger.warning("Unable to unpin all messages from {self}: {admin} is not an admin")
            raise BadPermission()

        with db.transaction():
            unpinned_files = [
                r[0]
                for r in query(
                    """
                    SELECT id FROM files
                    WHERE message IN (SELECT message FROM pinned_messages WHERE room = :r)
                    """,
                    r=self.id,
                )
            ]

            count = query("DELETE FROM pinned_messages WHERE room = :r", r=self.id).rowcount

            if unpinned_files:
                File.reset_expiries(unpinned_files)

            if count != 0:
                self._refresh()

        return count

    def unpin(self, msg_id: int, admin: User):
        """
        Unpins a pinned message in this room.  Requires admin privileges.  Returns the number of
        pinned messages actually removed (i.e. 0 or 1).
        """

        if not self.check_admin(admin):
            app.logger.warning("Unable to unpin message from {self}: {admin} is not an admin")
            raise BadPermission()

        with db.transaction():
            unpinned_files = [
                r[0]
                for r in query(
                    "SELECT id FROM files WHERE room = :r AND message = :m", r=self.id, m=msg_id
                )
            ]

            count = query(
                "DELETE FROM pinned_messages WHERE room = :r AND message = :m", r=self.id, m=msg_id
            ).rowcount

            if unpinned_files:
                File.reset_expiries(unpinned_files)

            if count != 0:
                self._refresh()

        return count

    @property
    def url(self):
        """
        URL of the web based room viewer for this room
        """
        return utils.server_url(self.token)

    @property
    def permissions(self):
        """
        export room permissions in full,
        returns a dict of session_id -> permissions dict (a dict of permission type to bool)
        """
        ret = dict()
        for row in query(
            """SELECT session_id, upo.* FROM user_permission_overrides upo
            JOIN users ON "user" = users.id WHERE room = :r""",
            r=self.id,
        ):
            data = dict()
            for k in row.keys():
                if row[k] is not None and k not in ('session_id', 'room', 'user'):
                    data[k] = bool(row[k])
            ret[row['session_id']] = data
        return ret

    def user_permissions(self, user):
        """
        Returns assigned room permissions for the given user.  Note that this does not reflect
        default permissions, but rather only permissions that have been specifically granted or
        revoked for this user.
        """
        row = query(
            'SELECT * from user_permission_overrides WHERE "user" = :u AND room = :r',
            u=user.id,
            r=self.id,
        ).fetchone()
        if not row:
            return {}
        return {
            k: bool(row[k]) for k in row.keys() if k not in ('room', 'user') and row[k] is not None
        }

    @property
    def future_permissions(self):
        """
        returns a list of future permission changes in this room
        """
        ret = list()
        for row in query(
            """
            SELECT session_id, futures.* FROM (
                SELECT "user", at, read, write, upload, NULL AS banned
                FROM user_permission_futures WHERE room = :r

                UNION ALL

                SELECT "user", at, NULL AS read, NULL AS write, NULL AS upload, banned
                FROM user_ban_futures WHERE room = :r
            ) futures JOIN users ON futures."user" = users.id
            ORDER BY at
            """,
            r=self.id,
        ):
            data = dict()
            for k in row.keys():
                if k == 'user':
                    continue
                if k in ('at', 'session_id'):
                    data[k] = row[k]
                elif row[k] is not None:
                    data[k] = bool(row[k])
            ret.append(data)
        return ret

    def user_future_permissions(self, user):
        """
        Returns a list of any scheduled future permission changes for the given user in this room
        (note that this includes bans as well as the read/write/upload permissions).
        """
        result = []
        for row in query(
            """
            SELECT * FROM (
                SELECT at, read, write, upload, null AS banned
                FROM user_permission_futures WHERE room = :r AND "user" = :u

                UNION ALL

                SELECT at, NULL AS read, NULL AS write, NULL AS upload, banned
                FROM user_ban_futures WHERE room = :r AND "user" = :u
            ) futures ORDER BY at
            """,
            u=user.id,
            r=self.id,
        ):
            result.append({k: bool(row[k]) for k in row.keys() if k != 'at' and row[k] is not None})
            result[-1]['at'] = row['at']

        return result


def get_rooms():
    """Get a list of all rooms; does not check permissions."""
    return [Room(row) for row in query("SELECT * FROM rooms ORDER BY token")]


def get_rooms_with_permission(
    user: User,
    *,
    tokens: Optional[Union[list, tuple]] = None,
    read: Optional[bool] = None,
    accessible: Optional[bool] = None,
    write: Optional[bool] = None,
    upload: Optional[bool] = None,
    banned: Optional[bool] = None,
    moderator: Optional[bool] = None,
    admin: Optional[bool] = None,
):
    """
    Returns a list of rooms that the given user has matching permissions for.

    Parameters:
    user: the user object to query permissions for.  May not be None.
    tokens: if non-None then this specifies a list or tuple of room tokens to filter by.  When
            omitted, all rooms are returned.  Note that rooms are returned sorted by token, *not* in
            the order specified here; duplicates are not returned; nor are entries for non-existent
            tokens.
    read/accessible/write/upload/banned/moderator/admin:
        Any of these that are specified as non-None must match the user's permissions for the room.
        For example `read=True, write=False` would return all rooms where the user has read-only
        access but not rooms in which the user has both or neither read and write permissions.
        At least one of these arguments must be specified as non-None.
    """
    if user is None:
        raise RuntimeError("user is required for get_rooms_with_permission")
    if not any(arg is not None for arg in (read, write, upload, banned, moderator, admin)):
        raise RuntimeError("At least one of read/write/upload/banned/moderator/admin must be given")
    if tokens and (
        not (isinstance(tokens, list) or isinstance(tokens, tuple))
        or any(not isinstance(t, str) for t in tokens)
    ):
        raise RuntimeError("tokens= must be a list or tuple of room token names")

    return [
        Room(row)
        for row in query(
            f"""
        SELECT rooms.* FROM user_permissions perm JOIN rooms ON rooms.id = room
        WHERE "user" = :u {'AND token IN :tokens' if tokens else ''}
            {'' if banned is None else ('AND' if banned else 'AND NOT') + ' perm.banned'}
            {'' if read is None else ('AND' if read else 'AND NOT') + ' perm.read'}
            {'' if accessible is None else ('AND' if accessible else 'AND NOT') +
                ' (perm.read OR perm.accessible)'}
            {'' if write is None else ('AND' if write else 'AND NOT') + ' perm.write'}
            {'' if upload is None else ('AND' if upload else 'AND NOT') + ' perm.upload'}
            {'' if moderator is None else ('AND' if moderator else 'AND NOT') + ' perm.moderator'}
            {'' if admin is None else ('AND' if admin else 'AND NOT') + ' perm.admin'}
        ORDER BY token
        """,
            u=user.id,
            tokens=tokens,
            bind_expanding=['tokens'] if tokens else None,
        )
    ]


def get_accessible_rooms(user: Optional[User] = None):
    """
    Get a list of rooms that a user can access; if user is None then return all publicly accessible
    rooms.
    """
    if user is None:
        result = query("SELECT * FROM rooms WHERE (read OR accessible) ORDER BY token")
    else:
        return get_rooms_with_permission(user, accessible=True, banned=False)
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
