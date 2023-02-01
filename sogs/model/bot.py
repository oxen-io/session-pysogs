from __future__ import annotations

from .. import crypto, db, config
from ..db import query
from ..web import app
from .exc import BadPermission, PostRateLimited
from .. import utils
from ..omq import send_mule
from .user import User
from .room import Room
from .message import Message
from .filter import SimpleFilter
from .exc import InvalidData

from typing import Optional, List, Union
import time


class Bot:
    """
    Class representing a simple bot to manage open group server

    Object Properties:
        id - database primary key for user row
        status - bot active(T)/passive(F) moderation status (key = room, value = bool)
        rooms - reference to room(s) in which bot is active
        filter - reference to filter object paired with bot
        perm_cache - dict storing user info/status (synced from all rooms patrolled)
        session_id - hex encoded session_id of the bot
        banned - default to false
        global_admin - default to true for bot
        global_moderator - default to true for bot
        visible_mod - default to true for bot
    """

    def __init__(
        self,
        _rooms: List[Room],
        row=None,
        *,
        id: Optional[int] = None,
        session_id: Optional[int] = None,
    ) -> None:
        # immutable attributes
        self._banned: bool = False
        self._global_admin: bool = False
        self._global_moderator: bool = False
        self._visible_mod: bool = False
        self.id = id

        # operational attributes
        self.rooms: List[Room] = _rooms
        self.status = {r: False for r in self.rooms}
        self.filter = SimpleFilter(_bot=self)
        self.perm_cache = {}
        self.current_message: Message = None
        self.nlp_model = None
        self.language = 'English'
        self.word_blacklist = ['placeholderlist', 'until', 'we', 'decide', 'naughty', 'words']

    def __setattr__(self, __name: str, __value) -> None:
        if __name in ['_banned', '_global_admin', '_global_moderator', '_visible_mod']:
            raise AttributeError('Cannot modify bots')
        else:
            setattr(self, __name, __value)

    def __delattr__(self, __name: str) -> None:
        if __name in ['_banned', '_global_admin', '_global_moderator', '_visible_mod']:
            raise AttributeError('Cannot modify bots')
        else:
            delattr(self, __name)

    def _link_room(self, _room: Room):
        self.rooms.append(_room)
        self.filter.rooms.append(_room)

    def _unlink_room(self, _room: Room):
        self.rooms.remove(_room)

        if not self.rooms:
            delete_bot_function_goes_here = True

    def _refresh_cache(self):
        for r in self.rooms:
            self.perm_cache = self.perm_cache | r._perm_cache

    def check_permission_for(
        self,
        room: Room,
        user: Optional[User] = None,
        *,
        admin=False,
        moderator=False,
        read=False,
        accessible=False,
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
                bool(room.default_read),
                bool(room.default_accessible),
                bool(room.default_write),
                bool(room.default_upload),
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

            (
                is_banned,
                can_read,
                can_access,
                can_write,
                can_upload,
                is_mod,
                is_admin,
            ) = self._perm_cache[user.id]

    # Shortcuts for check_permission calls
    def check_unbanned(self, room: Room, user: Optional[User]):
        return self.check_permission_for(room, user)

    def check_read(self, room: Room, user: Optional[User] = None):
        return self.check_permission_for(room, user, read=True)

    def check_accessible(self, room: Room, user: Optional[User] = None):
        return self.check_permission_for(room, user, accessible=True)

    def check_write(self, room: Room, user: Optional[User] = None):
        return self.check_permission_for(room, user, write=True)

    def check_upload(self, room: Room, user: Optional[User] = None):
        """Checks for both upload *and* write permission"""
        return self.check_permission_for(room, user, write=True, upload=True)

    def check_moderator(self, room: Room, user: Optional[User]):
        return self.check_permission_for(room, user, moderator=True)

    def check_admin(self, room: Room, user: Optional[User]):
        return self.check_permission_for(room, user, admin=True)

    def receive_message(
        self,
        room: Room,
        user: User,
        data: bytes,
        sig: bytes,
        *,
        whisper_to: Optional[Union[User, str]] = None,
        whisper_mods: bool = False,
        files: List[int] = [],
    ):
        if not self.check_write(user):
            raise BadPermission()

        if data is None or sig is None or len(sig) != 64:
            raise InvalidData()

        whisper_mods = bool(whisper_mods)
        if (whisper_to or whisper_mods) and not self.check_moderator(user):
            app.logger.warning(f"Cannot post a whisper to {room}: {user} is not a moderator")
            raise BadPermission()

        if whisper_to and not isinstance(whisper_to, User):
            whisper_to = User(session_id=whisper_to, autovivify=True, touch=False)

        filtered = self.filter.read_message(user, data, room)

        with db.transaction():
            if room.rate_limit_size and not self.check_admin(user):
                since_limit = time.time() - room.rate_limit_interval
                recent_count = query(
                    """
                    SELECT COUNT(*) FROM messages
                    WHERE room = :r AND "user" = :u AND posted >= :since
                    """,
                    r=self.id,
                    u=user.id,
                    since=since_limit,
                ).first()[0]

                if recent_count >= room.rate_limit_size:
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
                r=room.id,
                u=user.id,
                data=unpadded_data,
                data_size=data_size,
                signature=sig,
                filtered=filtered is not None,
                whisper=whisper_to.id if whisper_to else None,
                whisper_mods=whisper_mods,
            )

            if files:
                # Take ownership of any uploaded files attached to the post:
                room._own_files(msg_id, files, user)

            assert msg_id is not None
            row = query("SELECT posted, seqno FROM messages WHERE id = :m", m=msg_id).first()
            msg = {
                'id': msg_id,
                'session_id': user.session_id,
                'posted': row[0],
                'seqno': row[1],
                'data': data,
                'signature': sig,
                'reactions': {},
            }
            if filtered is not None:
                msg['filtered'] = True
            if whisper_to or whisper_mods:
                msg['whisper'] = True
                msg['whisper_mods'] = whisper_mods
                if whisper_to:
                    msg['whisper_to'] = whisper_to.session_id

        send_mule("message_posted", msg["id"])
        return msg
