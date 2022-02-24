import logging


def migrate(conn):
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

    if 'file_id_hacks' in db.metadata.tables:
        # If the table exists but is empty (i.e. because all the attachments expired) then we should
        # drop it.
        n_fid_hacks = conn.execute("SELECT COUNT(*) FROM file_id_hacks").first()[0]
        if n_fid_hacks == 0:
            logging.warning("Dropping file_id_hacks old sogs import table (no longer required)")
            db.metadata.tables['file_id_hacks'].drop(db.engine)
        else:
            logging.warning("Keeping file_id_hacks old sogs import table (still required)")
            global HAVE_FILE_ID_HACKS
            db.HAVE_FILE_ID_HACKS = True

    try:
        rows = conn.execute(
            "SELECT room, old_message_id_max, message_id_offset FROM room_import_hacks"
        )
        for (room, id_max, offset) in rows:
            db.ROOM_IMPORT_HACKS[room] = (id_max, offset)
    except Exception:
        pass
