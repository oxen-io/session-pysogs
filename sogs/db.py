from . import config
from . import crypto
import os
import sqlite3
import logging
import threading
import importlib.resources

HAVE_FILE_ID_HACKS = False
# roomid => (max, offset).  Max is the highest message id that was in the old table; offset is the
# value we add to ids <= that max to calculate the new database message id.
ROOM_IMPORT_HACKS = {}


_conns = threading.local()


def get_conn():
    """
    Returns a thread-local database connection, establishing the first time it is called within a
    thread.  This typically does not need to be called, instead use `cur()` or `tx()`.
    """
    if not hasattr(_conns, 'conn'):
        _conns.conn = sqlite_connect()
    return _conns.conn


def cur():
    """
    Returns a cursor on a thread-local database connection, establishing a new connection the first
    time it is called in thread.  A transaction is *not* started; if the code using the cursor is
    intending to change the database you probably want to use `tx()` instead.
    """
    return get_conn().cursor()


def execute(query, *parameters):
    """
    Constructs a cursor, executes a query on it, and returns the cursor.  Note that this is *not* in
    a transaction and so should only be used for selects.
    """
    c = cur()
    c.execute(query, *parameters)
    return c


class LocalTxContextManager:
    """
    Context manager that begins a transaction (with BEGIN IMMEDIATE, by default) and yields a cursor
    on entry, commits on normal exit, and rolls back on exit via exception.

    Internally this supports nesting via named savepoints with unique names on nested construction
    within a thread.

    Intended use is with a context to wrap code in a transaction (using the `tx` alias):

        with db.tx() as cur:
            ...

    Transactions are IMMEDIATE by default because SQLite's default DEFERRED transactions are a
    recipe for concurrency failure (see SQLITE_BUSY_SNAPSHOT description in
    https://www.sqlite.org/isolation.html).  If, however, you need transactional isolation for a
    read-only transaction (i.e. because you need multiple SELECTs that depend on a consistent
    snapshot of the data) then you can construct the transaction with the `read_only=True` kwarg to
    use a DEFERRED transaction.  (It is technically not read-only, but if you try to use
    modification on it you will probably end up crying at some future point).
    """

    def __init__(self, *, read_only=False):
        self.conn = get_conn()
        self.immediate = not read_only

    def __enter__(self):
        if not hasattr(_conns, 'sp_num'):
            _conns.sp_num = 1
        else:
            _conns.sp_num += 1

        self.sp_num = _conns.sp_num
        if self.sp_num == 1:
            self.conn.execute("BEGIN IMMEDIATE" if self.immediate else "BEGIN")
        else:
            self.conn.execute(f"SAVEPOINT sogs_sp_{self.sp_num}")

        return self.conn.cursor()

    def __exit__(self, exc_type, exc_value, traceback):
        _conns.sp_num -= 1
        if exc_type is None:
            # This can throw, which we want to propagate
            if self.sp_num == 1:
                self.conn.execute("COMMIT")
            else:
                self.conn.execute(f"RELEASE SAVEPOINT sogs_sp_{self.sp_num}")
        else:
            # We're exiting the context by exception, so try to rollback but if this also fails then
            # we want the original exception to propagate, not this one.
            try:
                if self.sp_num == 1:
                    self.conn.execute("ROLLBACK")
                else:
                    self.conn.execute(f"ROLLBACK TO SAVEPOINT sogs_sp_{self.sp_num}")
            except Exception as e:
                logging.warn(f"Failed to rollback database transaction: {e}")


# Shorter alias for convenience
tx = LocalTxContextManager


def sqlite_connect(path=config.DB_PATH):
    """
    Establishes and does basic setup of a new SQLite connection.  If path is given, open that;
    otherwise open the default database path.
    """

    if path is None:
        path = config.DB_PATH

    conn = sqlite3.connect(path, isolation_level=None)
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
        conn.executescript(importlib.resources.read_text('sogs', 'schema.sql'))

    # Database migrations/updates/etc.
    migrate_v01x(conn)
    add_new_columns(conn)
    update_message_views(conn)
    create_message_details_deleter(conn)
    check_for_hacks(conn)

    # Make sure the system admin users exists
    create_admin_user(conn)

    conn.close()


def migrate_v01x(conn):
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


def add_new_columns(conn):
    # New columns that might need to be added:
    new_table_cols = {
        'messages': {
            'whisper': 'INTEGER REFERENCES users(id)',
            'whisper_mods': 'BOOLEAN NOT NULL DEFAULT FALSE',
            'filtered': 'BOOLEAN NOT NULL DEFAULT FALSE',
        },
        'user_permission_futures': {'banned': 'BOOLEAN'},
    }

    for table, cols in new_table_cols.items():
        with conn:
            existing = {c['name'] for c in conn.execute(f"PRAGMA table_info('{table}')")}
            for name, definition in cols.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def update_message_views(conn):
    cols = [c['name'] for c in conn.execute("PRAGMA table_info('message_metadata')")]
    if any(x not in cols for x in ('whisper_to', 'filtered')):
        with conn:
            conn.execute("DROP VIEW IF EXISTS message_metadata")
            conn.execute("DROP VIEW IF EXISTS message_details")
            conn.execute(
                """
CREATE VIEW message_details AS
SELECT messages.*, uposter.session_id, uwhisper.session_id AS whisper_to
    FROM messages
        JOIN users uposter ON messages.user = uposter.id
        LEFT JOIN users uwhisper ON messages.whisper = uwhisper.id
"""
            )
            conn.execute(
                """
CREATE VIEW message_metadata AS
SELECT id, room, user, session_id, posted, edited, updated, filtered, whisper_to,
        length(data) AS data_unpadded, data_size, length(signature) as signature_length
    FROM message_details
"""
            )


def create_message_details_deleter(conn):
    conn.execute(
        """
CREATE TRIGGER IF NOT EXISTS message_details_deleter INSTEAD OF DELETE ON message_details
FOR EACH ROW WHEN OLD.data IS NOT NULL
BEGIN
    UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
        WHERE id = OLD.id;
END
"""
    )


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


def create_admin_user(conn):
    """
    We create a dummy user (with id 0) for system tasks such as changing moderators from
    command-line, and give it the server's x25519 pubkey (with ff prepended, *not* 05) as a fake
    default session_id.
    """
    conn.execute(
        """
        INSERT INTO users (id, session_id, moderator, admin, visible_mod)
            VALUES (0, ?1, TRUE, TRUE, FALSE)
        ON CONFLICT (id) DO UPDATE
            SET session_id = ?1, moderator = TRUE, admin = TRUE, visible_mod = FALSE
        """,
        ("ff" + crypto.server_pubkey_hex,),
    )


database_init()
