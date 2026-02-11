import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """
    The 0.1.x migration sets up a file_id_hacks table to map old ids to new ids; if it's present and
    non-empty then we enable "hack" mode.  (This should empty out over 15 days as attachments
    expire).

    We also have a room_import_hacks table that lets us map old message ids to new ids (because in
    the old database message ids overlapped, but in the new database they are unique).  The consists
    of a max id and an offset that lets us figure out the new (current database) id.  For instance,
    some range of messages in room xyz with old ids [1,5000] could get inserted as ids [4321, 9320],
    so max would be 5000 and offset would be 4320: old message id 3333 will have new message id
    3333+4320 = 7653.  We read all the offsets once at startup and stash them in ROOM_IMPORT_HACKS.
    """

    from .. import db

    changed = False

    # Older version of the table edit migration didn't drop the old table:
    if 'old_room_import_hacks' in db.metadata.tables:
        logging.warning("Dropping old_room_import_hacks temporary table")
        if check_only:
            raise DatabaseUpgradeRequired("old_room_import_hacks")
        conn.execute('DROP TABLE old_room_import_hacks')
        changed = True

    if 'file_id_hacks' in db.metadata.tables:
        # If the table exists but is empty (i.e. because all the attachments expired) then we should
        # drop it.
        if not check_only and conn.execute("SELECT COUNT(*) FROM file_id_hacks").first()[0] == 0:
            logging.warning("Dropping file_id_hacks old sogs import table (no longer required)")
            db.metadata.tables['file_id_hacks'].drop(db.engine)
            changed = True
        else:
            logging.warning("Keeping file_id_hacks old sogs import table (still required)")
            db.HAVE_FILE_ID_HACKS = True

    if 'room_import_hacks' in db.metadata.tables:
        rows = conn.execute(
            "SELECT room, old_message_id_max, message_id_offset FROM room_import_hacks"
        )
        for room, id_max, offset in rows:
            db.ROOM_IMPORT_HACKS[room] = (id_max, offset)

    if not db.HAVE_FILE_ID_HACKS and 'room_import_hacks' not in db.metadata.tables:
        return changed

    # DB fix: the original import was missing a ON DELETE CASCADE on the rooms foreign key,
    # which prevents imported room deletion.

    if db.engine.name == 'sqlite':
        # SQLite can't add a foreign key, so we have to rename, recreate entirely, and copy
        # everything over.  Ew.
        if db.HAVE_FILE_ID_HACKS:
            need_fix = False
            # Annoyingly, sqlalchemy doesn't pick up foreign key actions when reflecting
            # sqlite (probably because sqlite doesn't enforce foreign keys by default), so
            # we have to pragma query the info ourself:
            for fk in conn.execute('PRAGMA foreign_key_list("file_id_hacks")'):
                if fk['from'] == 'room' and fk['on_delete'] != 'CASCADE':
                    need_fix = True
            if need_fix:
                logging.warning("Replacing file_id_hacks to add cascading foreign key")
                if check_only:
                    raise DatabaseUpgradeRequired("file_id_hacks")
                conn.execute("ALTER TABLE file_id_hacks RENAME TO old_file_id_hacks")
                conn.execute(
                    """
CREATE TABLE file_id_hacks (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    old_file_id INTEGER NOT NULL,
    file INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    PRIMARY KEY(room, old_file_id)
)
                    """
                )
                conn.execute(
                    """
                    INSERT INTO file_id_hacks
                    SELECT room, old_file_id, file FROM old_file_id_hacks
                    """
                )

                changed = True

        if 'room_import_hacks' in db.metadata.tables:
            need_fix = False
            # Annoyingly, sqlalchemy doesn't pick up foreign key actions when reflecting
            # sqlite (probably because sqlite doesn't enforce foreign keys by default), so
            # we have to pragma query the info ourself:
            for fk in conn.execute('PRAGMA foreign_key_list("room_import_hacks")'):
                if fk['from'] == 'room' and fk['on_delete'] != 'CASCADE':
                    need_fix = True
            if need_fix:
                logging.warning("Replacing room_import_hacks to add cascading foreign key")
                if check_only:
                    raise DatabaseUpgradeRequired("room_import_hacks")
                conn.execute("ALTER TABLE room_import_hacks RENAME TO old_room_import_hacks")
                conn.execute(
                    """
CREATE TABLE room_import_hacks (
    room INTEGER PRIMARY KEY NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    old_message_id_max INTEGER NOT NULL,
    message_id_offset INTEGER NOT NULL
)
                    """
                )
                conn.execute(
                    """
                    INSERT INTO room_import_hacks
                    SELECT room, old_message_id_max, message_id_offset
                        FROM old_room_import_hacks
                    """
                )
                conn.execute('DROP TABLE old_room_import_hacks')

                changed = True

    else:  # postgresql
        fix_fid = db.HAVE_FILE_ID_HACKS and any(
            f.ondelete != 'CASCADE'
            for f in db.metadata.tables['file_id_hacks'].c['room'].foreign_keys
        )
        fix_room = 'room_import_hacks' in db.metadata.tables and any(
            f.ondelete != 'CASCADE'
            for f in db.metadata.tables['room_import_hacks'].c['room'].foreign_keys
        )
        if fix_fid or fix_room:
            if check_only:
                raise DatabaseUpgradeRequired("v0.1.x import hacks tables")
            if fix_fid:
                conn.execute(
                    """
ALTER TABLE file_id_hacks DROP CONSTRAINT file_id_hacks_room_fkey;
ALTER TABLE file_id_hacks ADD CONSTRAINT
file_id_hacks_room_fkey FOREIGN KEY (room) REFERENCES rooms(id);
                    """
                )
            if fix_room:
                conn.execute(
                    """
ALTER TABLE room_import_hacks DROP CONSTRAINT room_import_hacks_room_fkey;
ALTER TABLE room_import_hacks ADD CONSTRAINT
room_import_hacks_room_fkey FOREIGN KEY (room) REFERENCES rooms(id);
                    """
                )
            changed = True

    return changed
