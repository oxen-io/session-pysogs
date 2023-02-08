from __future__ import annotations

from .. import crypto, db, config
from ..db import query
from ..web import app
from .exc import BadPermission, PostRateLimited
from .. import utils
from ..omq import send_mule
from .user import User
from .bot import Bot
from .room import Room
from .message import Message
from .filter import SimpleFilter
from .exc import InvalidData
import heapq

from dataclasses import dataclass, field
from typing import Optional, List, Union, Any
import time

"""
Complications:
    - given captcha bot
        - new user (not approved) posts message
        - we need bot to reply with whisper to that user with simple problem
        - what does the bot do with the message they tried to send?
            - can store locally
            - user sends reply
            - bot inserts it into room (?)

Control Flow:
    1) message comes in HTTP request
    2) unpacked/parsed/verified/permissions checked
    3) comes into relevant route (ex: add_post())
    4) sends off to mule to be handled by bots
    5) mule has ordered list of bots by priority
    6) mule passes message to bots, which have fixed return values (insert, do not insert)
    7) if all bots approve, mule replies to worker with go ahead or vice versa for no go
"""


@dataclass(order=True)
class PriorityTuple(tuple):
    priority: int
    item: Any = field(compare=False)


# Simple "priority queue" of bots implemented using a dict with heap
# invariance maintained by qheap algorithm
# TODO: when bots are designed basically, add methods for polling them
#   and receiving their judgments
class BotQueue:
    def __init__(self) -> None:
        self.queue = {}

    def _qsize(self) -> int:
        return len(self.queue.keys())

    def _empty(self) -> bool:
        return not self._qsize()

    def _peek(self, priority: int):
        return self.queue.get(priority)

    def _put(self, item: PriorityTuple):
        temp = list(self.queue.items())
        heapq.heappush(temp, item)
        self.queue = dict(temp)

    def _get(self):
        return heapq.heappop(self.queue)


class Manager:
    """
    Class representing an interface that manages active bots

    Object Properties:
        queue - BotQueue object
    """

    def __init__(
        self,
        _rooms: List[Room],
        row=None,
        *,
        id: Optional[int] = None,
        session_id: Optional[int] = None,
    ) -> None:
        self.id = id
        self.queue = BotQueue()

    def qempty(self):
        return not self.queue._empty()

    def add_bot(self, bot: Bot, priority: int = None):
        if not priority:
            # if no priority is given, lowest priority is assigned
            priority = self.qsize()
        else:
            # if priority is already taken, find next lowest
            while self.queue.get(priority):
                priority += 1
        self.queue._put(PriorityTuple(priority, bot))

    def remove_bot(self):
        do_something = 3

    def peek(self, priority: int):
        return self.queue._peek(priority)

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

        if room._bot_status():
            add_bot_logic = 3
            """
                TODO: add logic for bots receiving message and doing
                bot things. The bots should be queried in terms of
                priority,
            """

        send_mule("message_posted", msg["id"])
        return msg
