from __future__ import annotations

from .. import crypto, db, config
from ..db import query
from ..web import app
from .exc import NoSuchUser, BadPermission

from typing import Optional
import time


class User:
    """
    Class representing a user stored in the database.

    Properties:
        id - the database primary key for this user row
        session_id - the session_id of the user, in hex
        created - unix timestamp when the user was created
        last_active - unix timestamp when the user was last active
        banned - True if the user is (globally) banned
        global_admin - True if the user is a global admin
        global_moderator - True if the user is a global moderator
        visible_mod - True if the user's admin/moderator status should be visible in rooms
    """

    def __init__(self, row=None, *, id=None, session_id=None, autovivify=True, touch=False):
        """
        Constructs a user from a pre-retrieved row *or* a session id or user primary key value.

        autovivify - if True and we are given a session_id that doesn't exist, either consider
        importing from a pre-blinding user (if needed) or create a default user row and use it to
        populate the object.  This is the default behaviour.  If False and the session_id doesn't
        exist then a NoSuchUser is raised if the session id doesn't exist.

        touch - if True (default is False) then update the last_activity time of this user before
        returning it.
        """
        self._touched = False
        self._refresh(row=row, id=id, session_id=session_id, autovivify=autovivify)

        if touch:
            self._touch()

    def _refresh(self, *, row=None, id=None, session_id=None, autovivify=True):
        """
        Internal method to (re-)fetch details from the database; this is used during construction
        but also in the test suite to forcibly re-fetch details.
        """
        n_args = sum(x is not None for x in (row, session_id, id))
        if n_args == 0 and hasattr(self, 'id'):
            id = self.id
        elif n_args != 1:
            raise ValueError("User() error: exactly one of row/session_id/id is required")

        if session_id is not None:
            row = query("SELECT * FROM users WHERE session_id = :s", s=session_id).first()

            if not row and autovivify:
                if config.REQUIRE_BLIND_KEYS:
                    row = self._import_blinded(session_id)

                if not row:
                    row = db.insert_and_get_row(
                        "INSERT INTO users (session_id) VALUES (:s)", "users", "id", s=session_id
                    )
                    # No need to re-touch this user since we just created them:
                    self._touched = True

        elif id is not None:
            row = query("SELECT * FROM users WHERE id = :u", u=id).fetchone()

        if row is None:
            raise NoSuchUser(session_id if session_id is not None else id)

        self.id, self.session_id, self.created, self.last_active = (
            row[c] for c in ('id', 'session_id', 'created', 'last_active')
        )
        self.banned, self.global_moderator, self.global_admin, self.visible_mod = (
            bool(row[c]) for c in ('banned', 'moderator', 'admin', 'visible_mod')
        )

    def _import_blinded(self, session_id):
        """
        Attempts to import the user and permission rows from an unblinded session_id to a new,
        blinded session_id row.

        Any permissions/bans are *moved* from the old, unblinded id to the new blinded user record.
        """

        if not session_id.startswith('15'):
            return
        blind_abs = crypto.blinded_abs(session_id.lower())
        with db.transaction():
            to_import = query(
                """
                SELECT * FROM users WHERE id = (
                    SELECT "user" FROM needs_blinding WHERE blinded_abs = :ba
                )
                """,
                ba=blind_abs,
            ).fetchone()

            if to_import is None:
                return False

            row = db.insert_and_get_row(
                """
                INSERT INTO users
                    (session_id, created, last_active, banned, moderator, admin, visible_mod)
                VALUES (:sid, :cr, :la, :ban, :mod, :admin, :vis)
                """,
                "users",
                "id",
                sid=session_id,
                cr=to_import["created"],
                la=to_import["last_active"],
                ban=to_import["banned"],
                mod=to_import["moderator"],
                admin=to_import["admin"],
                vis=to_import["visible_mod"],
            )
            # If we have any global ban/admin/mod then clear them (because we've just set up the
            # global ban/mod/admin permissions for the blinded id in the query above).
            query(
                "UPDATE users SET banned = FALSE, admin = FALSE, moderator = FALSE WHERE id = :u",
                u=to_import["id"],
            )

            for t in ("user_permission_overrides", "user_permission_futures", "user_ban_futures"):
                query(
                    f'UPDATE {t} SET "user" = :new WHERE "user" = :old',
                    new=row["id"],
                    old=to_import["id"],
                )

            query('DELETE FROM needs_blinding WHERE "user" = :u', u=to_import["id"])

            return row

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

    def _touch(self):
        query(
            """
            UPDATE users SET last_active = :now
            WHERE id = :u
            """,
            u=self.id,
            now=time.time(),
        )
        self._touched = True

    def touch(self, force=False):
        """
        Updates the last activity time of this user.  This method only updates the first time it is
        called (and possibly not even then, if we auto-vivified the user row), unless `force` is set
        to True.
        """
        if not self._touched or force:
            self._touch()

    def update_room_activity(self, room):
        query(
            """
            INSERT INTO room_users ("user", room) VALUES (:u, :r)
            ON CONFLICT("user", room) DO UPDATE
            SET last_active = :now
            """,
            u=self.id,
            r=room.id,
            now=time.time(),
        )

    def set_moderator(self, *, added_by: User, admin=False, visible=False):
        """
        Make this user a global moderator or admin.  If the user is already a global mod/admin then
        their status is updated according to the given arguments (that is, this can promote/demote).

        If `admin` is None then the current admin status is left unchanged.
        """

        if not added_by.global_admin:
            app.logger.warning(
                f"Cannot set {self} as global {'admin' if admin else 'moderator'}: "
                f"{added_by} is not a global admin"
            )
            raise BadPermission()

        query(
            f"""
            UPDATE users
            SET moderator = TRUE, visible_mod = :visible
                {', admin = :admin' if admin is not None else ''}
            WHERE id = :u
            """,
            admin=bool(admin),
            visible=visible,
            u=self.id,
        )
        self.global_admin = admin
        self.global_moderator = True
        self.visible_mod = visible

    def remove_moderator(self, *, removed_by: User, remove_admin_only: bool = False):
        """Removes this user's global moderator/admin status, if set."""

        if not removed_by.global_admin:
            app.logger.warning(
                f"Cannot remove {self} as global mod/admin: {removed_by} is not an admin"
            )
            raise BadPermission()

        query(
            f"""
            UPDATE users
            SET admin = FALSE {', moderator = FALSE' if not remove_admin_only else ''}
            WHERE id = :u
            """,
            u=self.id,
        )
        self.global_admin = False
        self.global_moderator = False

    def ban(self, *, banned_by: User, timeout: Optional[float] = None):
        """
        Globally bans this user from the server; can only be applied by a global moderator or global
        admin, and cannot be applied to another global moderator or admin (to prevent accidental
        mod/admin banning; to ban them, first explicitly remove them as moderator/admin and then
        ban).

        timeout should be None for a non-expiring ban and otherwise should be the duration of the
        ban, in seconds; an unban will be scheduled to occur after the interval.  In either case,
        any existing scheduled global unbans for this user will be deleted (and replaced, if a new
        timeout is provided).
        """

        if not banned_by.global_moderator:
            app.logger.warning(f"Cannot ban {self}: {banned_by} is not a global mod/admin")
            raise BadPermission()

        if self.global_moderator:
            app.logger.warning(f"Cannot ban {self}: user is a global moderator/admin")
            raise BadPermission()

        with db.transaction():
            query("UPDATE users SET banned = TRUE WHERE id = :u", u=self.id)
            query(
                'DELETE FROM user_ban_futures WHERE room IS NULL AND "user" = :u AND NOT banned',
                u=self.id,
            )

            if timeout:
                query(
                    """
                    INSERT INTO user_ban_futures
                    ("user", room, banned, at) VALUES (:u, NULL, FALSE, :at)
                    """,
                    u=self.id,
                    at=time.time() + timeout,
                )

        app.logger.debug(
            f"{banned_by} globally banned {self}{f' for {timeout}s' if timeout else ''}"
        )
        self.banned = True

    def unban(self, *, unbanned_by: User):
        """
        Undoes a global ban.  `unbanned_by` must be a global mod/admin.

        Any currently scheduled global ban futures for this user will be removed as well.
        """
        if not unbanned_by.global_moderator:
            app.logger.warning(f"Cannot unban {self}: {unbanned_by} is not a global mod/admin")
            raise BadPermission()

        query("UPDATE users SET banned = FALSE WHERE id = :u", u=self.id)
        query(
            'DELETE FROM user_ban_futures WHERE room IS NULL AND "user" = :u AND banned', u=self.id
        )

        app.logger.debug(f"{unbanned_by} removed global ban on {self}")
        self.banned = False

    def verify(self, *, message: bytes, sig: bytes):
        """verify signature signed by this session id
        return True if the signature is valid otherwise return False
        """
        pk = crypto.xed25519_pubkey(bytes.fromhex(self.session_id[2:]))
        return crypto.verify_sig_from_pk(message, sig, pk)

    @property
    def is_blinded(self):
        """True if the user's session id is a derived key"""
        return self.session_id[0:2] == '15'

    @property
    def system_user(self):
        """True if (and only if) this is the special SOGS system user
        created for internal database tasks"""
        return self.session_id[0:2] == "ff" and self.session_id[2:] == crypto.server_pubkey_hex


class SystemUser(User):
    """
    User subclasses representing the local system for performing local operations, e.g. from the
    command line.
    """

    def __init__(self):
        super().__init__(session_id="ff" + crypto.server_pubkey_hex)


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
    for row in query("SELECT * FROM users WHERE moderator"):
        u = User(row=row)
        if u.system_user:
            continue
        lst = (a if u.global_admin else m) if u.visible_mod else (ha if u.global_admin else hm)
        lst.append(u)

    return (m, a, hm, ha)
