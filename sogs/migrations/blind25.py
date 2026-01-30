import logging
from .exc import DatabaseUpgradeRequired
from sqlalchemy.schema import UniqueConstraint


def update_views(conn):
    conn.execute("DROP VIEW IF EXISTS room_moderators")
    conn.execute(
        """
CREATE VIEW room_moderators AS
SELECT COALESCE(users.last_id, users.session_id) as session_id, mods.* FROM (
    SELECT
        room,
        "user",
        -- visible_mod gets priority from the per-room row if it exists, so we use 3/2 for the
        -- per-room value below, 1/0 for the global value, take the max, then look for an odd value
        -- to give us the visibility bit:
        MAX(visible_mod) & 1 AS visible_mod,
        MAX(admin) AS admin,
        MAX(room_moderator) AS room_moderator,
        MAX(global_moderator) AS global_moderator
    FROM (
        SELECT
            room,
            "user",
            CASE WHEN visible_mod THEN 3 ELSE 2 END AS visible_mod,
            admin,
            TRUE AS room_moderator,
            FALSE AS global_moderator
        FROM user_permission_overrides WHERE moderator

        UNION ALL

        SELECT
            rooms.id AS room,
            users.id as "user",
            CASE WHEN visible_mod THEN 1 ELSE 0 END AS visible_mod,
            admin,
            FALSE as room_moderator,
            TRUE as global_moderator
        FROM users CROSS JOIN rooms WHERE moderator
    ) m GROUP BY "user", room
) mods JOIN users on "user" = users.id;
"""
    )


def migrate(conn, *, check_only):
    """
    Migrates any 05 or 15 session_id in users to 25 and updates references to
    that table accordingly, de-duplicating as necessary as well
    """

    from .. import db, crypto

    have_alt_id = False
    have_last_id = False

    if 'alt_id' in db.metadata.tables['messages'].c:
        have_alt_id = True

    if 'last_id' in db.metadata.tables['users'].c:
        have_last_id = True

    if have_alt_id and have_last_id:
        return False

    if check_only:
        raise DatabaseUpgradeRequired("Tables need to be migrated to 25-blinded")

    logging.warning("DB migration: Migrating tables to 25-blinded only")

    conn.execute(f"ALTER TABLE users ADD COLUMN last_id TEXT")
    update_views(conn)

    if have_alt_id:  # only need to add last_id column to users
        for row in db.query("SELECT id FROM users", dbconn=conn):
            user_id = row["id"]
            for alt_id_row in db.query(
                "SELECT alt_id FROM messages WHERE user = :user_id and alt_id IS NOT NULL LIMIT 1",
                user_id=user_id,
                dbconn=conn,
            ).all():
                conn.execute(
                    "UPDATE users SET last_id = :alt_id WHERE id = :user_id",
                    alt_id=alt_id_row['alt_id'],
                    user_id=user_id,
                )
        return True

    conn.execute(f"ALTER TABLE messages ADD COLUMN alt_id TEXT")
    conn.execute(f"ALTER TABLE inbox ADD COLUMN alt_id TEXT")

    user_rows_15 = db.query("SELECT * FROM users WHERE session_id LIKE '15%'", dbconn=conn)
    for row in user_rows_15.all():
        b15_id = row["session_id"]
        rowid = row["id"]
        b25 = crypto.compute_blinded25_id_from_15(b15_id)

        conn.execute("UPDATE users SET last_id = :b15_id WHERE session_id = :b15_id", b15_id=b15_id)
        conn.execute(
            'UPDATE users SET session_id = :b25 WHERE session_id = :b15_id', b25=b25, b15_id=b15_id
        )
        conn.execute(
            'UPDATE messages SET alt_id = :b15_id WHERE "user" = :rowid', b15_id=b15_id, rowid=rowid
        )
        conn.execute(
            'UPDATE inbox SET alt_id = :b15_id WHERE "sender" = :rowid', b15_id=b15_id, rowid=rowid
        )

    user_rows_05 = db.query("SELECT * FROM users WHERE session_id LIKE '05%'", dbconn=conn)
    for row in user_rows_05.all():
        b05_id = row["session_id"]
        rowid = row["id"]
        b25 = crypto.compute_blinded25_id_from_05(b05_id)

        new_row = db.query(
            "SELECT id FROM users WHERE session_id = :b25", b25=b25, dbconn=conn
        ).first()

        # if there were both 05 and 15 user rows for the 25 key, drop the 05 row and point references
        # to it to the (modified to 25 above) old 15 row, else do basically as above for the 15 rows
        # if both were present, update tables referencing users to reference the 25 row
        if new_row:
            rowid = new_row["id"]
            conn.execute(
                'UPDATE messages SET whisper = :rowid WHERE whisper = :oldrow',
                rowid=rowid,
                oldrow=row["id"],
            )
            conn.execute(
                'UPDATE messages SET user = :rowid, alt_id = :b05_id WHERE user = :oldrow',
                rowid=rowid,
                b05_id=b05_id,
                oldrow=row["id"],
            )
            conn.execute(
                'UPDATE pinned_messages SET pinned_by = :rowid WHERE pinned_by = :oldrow',
                rowid=rowid,
                oldrow=row["id"],
            )
            conn.execute(
                'UPDATE files SET uploader = :rowid WHERE uploader = :oldrow',
                rowid=rowid,
                oldrow=row["id"],
            )
            conn.execute(
                'UPDATE user_reactions SET "user" = :rowid WHERE "user" = :oldrow ON CONFLICT IGNORE',
                rowid=rowid,
                oldrow=row["id"],
            )
            conn.execute(
                'UPDATE room_users SET "user" = :rowid WHERE "user" = :oldrow ON CONFLICT IGNORE',
                rowid=rowid,
                oldrow=row["id"],
            )
            conn.execute(
                'UPDATE inbox SET recipient = :rowid WHERE recipient = :oldrow',
                rowid=rowid,
                oldrow=row["id"],
            )
            conn.execute(
                'UPDATE inbox SET sender = :rowid, alt_id = :b05_id WHERE sender = :oldrow',
                rowid=rowid,
                b05_id=b05_id,
                oldrow=row["id"],
            )
            conn.execute('DELETE FROM users WHERE id = :oldrow', oldrow=row["id"])
        else:
            conn.execute(
                "UPDATE users SET last_id = :b05_id WHERE session_id = :b05_id", b05_id=b05_id
            )
            conn.execute(
                'UPDATE users SET session_id = :b25 WHERE session_id = :b05_id',
                b25=b25,
                b05_id=b05_id,
            )

        conn.execute(
            'UPDATE messages SET alt_id = :b05_id WHERE "user" = :rowid', b05_id=b05_id, rowid=rowid
        )

    return True
