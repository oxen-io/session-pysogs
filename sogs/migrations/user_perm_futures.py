import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """
    Break up user_permission_futures to not be (room,user) unique, and to move ban futures to a
    separate table.
    """

    from .. import db

    if 'user_ban_futures' in db.metadata.tables:
        return False

    logging.warning("Updating user_permission_futures")
    if check_only:
        raise DatabaseUpgradeRequired("user_permission_futures/user_ban_futures conversion")

    if db.engine.name == 'sqlite':
        # Under sqlite we have to drop and recreate the whole thing.  (Since we didn't have a
        # release out that was using futures yet, we don't bother trying to migrate data).
        conn.execute("DROP TABLE user_permission_futures")
        conn.execute(
            """
CREATE TABLE user_permission_futures (
    room INTEGER NOT NULL REFERENCES rooms ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    at FLOAT NOT NULL, /* when the change should take effect (unix epoch) */
    read BOOLEAN, /* Set this value @ at, if non-null */
    write BOOLEAN, /* Set this value @ at, if non-null */
    upload BOOLEAN /* Set this value @ at, if non-null */
)
"""
        )
        conn.execute("CREATE INDEX user_permission_futures_at ON user_permission_futures(at)")
        conn.execute(
            """
CREATE INDEX user_permission_futures_room_user ON user_permission_futures(room, user)
"""
        )

        conn.execute(
            """
CREATE TABLE user_ban_futures (
    room INTEGER REFERENCES rooms ON DELETE CASCADE,
    user INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    at FLOAT NOT NULL, /* when the change should take effect (unix epoch) */
    banned BOOLEAN NOT NULL /* if true then ban at `at`, if false then unban */
);
"""
        )
        conn.execute("CREATE INDEX user_ban_futures_at ON user_ban_futures(at)")
        conn.execute("CREATE INDEX user_ban_futures_room_user ON user_ban_futures(room, user)")

    else:  # postgresql
        conn.execute(
            """
CREATE TABLE user_ban_futures (
    room INTEGER REFERENCES rooms ON DELETE CASCADE,
    "user" INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    at FLOAT NOT NULL, /* when the change should take effect (unix epoch) */
    banned BOOLEAN NOT NULL /* if true then ban at `at`, if false then unban */
);
CREATE INDEX user_ban_futures_at ON user_ban_futures(at);
CREATE INDEX user_ban_futures_room_user ON user_ban_futures(room, "user");

INSERT INTO user_ban_futures (room, "user", at, banned)
    SELECT room, "user", at, banned FROM user_permission_futures WHERE banned is NOT NULL;

DELETE FROM user_permission_futures WHERE read IS NULL AND write IS NULL AND uploads IS NULL;

ALTER TABLE user_permission_futures DROP CONSTRAINT IF EXISTS user_permission_futures_pkey;
ALTER TABLE user_permission_futures DROP COLUMN banned;
"""
        )

    return True
