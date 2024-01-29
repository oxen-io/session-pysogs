import logging
from .exc import DatabaseUpgradeRequired
from sqlalchemy.schema import UniqueConstraint


def migrate(conn, *, check_only):
    """
    Migrates any 05 or 15 session_id in users to 25 and updates references to
    that table accordingly, de-duplicating as necessary as well
    """

    from .. import db, crypto

    if 'alt_id' in db.metadata.tables['messages'].c:
        return False

    if check_only:
        raise DatabaseUpgradeRequired("Tables need to be migrated to 25-blinded")

    logging.warning("DB migration: Migrating tables to 25-blinded only")

    conn.execute(f"ALTER TABLE messages ADD COLUMN alt_id TEXT")
    conn.execute(f"ALTER TABLE inbox ADD COLUMN alt_id TEXT")

    user_rows_15 = db.query("SELECT * FROM users WHERE session_id LIKE '15%'", dbconn=conn)
    for row in user_rows_15.all():
        b15_id = row["session_id"]
        rowid = row["id"]
        b25 = crypto.compute_blinded25_id_from_15(b15_id)

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
                'UPDATE users SET session_id = :b25 WHERE session_id = :b05_id',
                b25=b25,
                b05_id=b05_id,
            )

        conn.execute(
            'UPDATE messages SET alt_id = :b05_id WHERE "user" = :rowid', b05_id=b05_id, rowid=rowid
        )

    return True
