from . import config
from .postfork import postfork
import os
import sqlite3
import logging


conn = None
HAVE_FILE_ID_HACKS = False
# roomid => (max, offset).  Max is the highest message id that was in the old table; offset is the
# value we add to ids <= that max to calculate the new database message id.
ROOM_IMPORT_HACKS = {}


def sqlite_connect(path=config.DB_PATH):
    """
    Establishes and does basic setup of a new SQLite connection.  If path is given, open that;
    otherwise open the default database path.
    """

    if path is None:
        path = config.DB_PATH

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")

    return conn


def database_init():
    """
    Perform database initialization: constructs the schema, if necessary, and performs any required
    migrations.  This does so using its *own* database connection, and is intended to be called
    during initialization *before* forking happens during uwsgi startup.
    """

    conn = sqlite_connect()
    have_messages = conn.execute(
        """
        SELECT EXISTS(
            SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages'
        )
        """
    ).fetchone()[0]

    if not have_messages:
        logging.warn("No database detected; creating new database schema")
        with open(config.DB_SCHEMA_FILE) as f, conn:
            conn.executescript(f.read())

    n_rooms = conn.execute("SELECT COUNT(*) FROM rooms").fetchone()[0]

    # Migration from a v0.1.x database:
    if n_rooms == 0 and os.path.exists("database.db"):
        logging.warn("No rooms found, but database.db exists; attempting migration")
        from . import migrate01x

        try:
            migrate01x.migrate01x(conn)
        except Exception:
            logging.critical(
                "database.db exists but migration failed!  Please report this bug!\n\n"
                "If no migration from 0.1.x is needed then rename or delete database.db to "
                "start up with a fresh (new) database.\n\n"
            )
            raise

    # Any future migrations go here

    check_for_hacks(conn)

    conn.close()


def check_for_hacks(conn):
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
    if conn.execute(
        """
        SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'file_id_hacks')
        """
    ).fetchone()[0]:
        # If the table exists but is empty (i.e. because all the attachments expired) then we should
        # drop it.
        n_fid_hacks = conn.execute("SELECT COUNT(*) FROM file_id_hacks").fetchone()[0]
        if n_fid_hacks == 0:
            conn.execute("DROP TABLE file_id_hacks")
        else:
            global HAVE_FILE_ID_HACKS
            HAVE_FILE_ID_HACKS = True

    try:
        rows = conn.execute(
            "SELECT room, old_message_id_max, message_id_offset FROM room_import_hacks"
        )
        for (room, id_max, offset) in rows:
            ROOM_IMPORT_HACKS[room] = (id_max, offset)
    except Exception:
        pass


database_init()


@postfork
def sqlite_connect_postfork():
    """
    Establishes a new sqlite per-process database connection after wsgi forks us.
    """
    global conn
    conn = sqlite_connect()
