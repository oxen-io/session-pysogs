from . import config
from . import crypto
from .postfork import postfork
import os
import logging
import importlib.resources
import sqlalchemy

HAVE_FILE_ID_HACKS = False
# roomid => (max, offset).  Max is the highest message id that was in the old table; offset is the
# value we add to ids <= that max to calculate the new database message id.
ROOM_IMPORT_HACKS = {}


def get_conn():
    """Gets a connection from the database engine connection pool.  This is not intended to be used
    by flask endpoints: they should use web.appdb instead (which calls this upon first use)."""
    return engine.connect()


def query(query, *, dbconn=None, **params):
    """Executes a query containing :param style placeholders (regardless of the actual underlying
    database placeholder style), binding them using the given params keyword arguments.

    Note that, if the query contains a literal : it must be escaped as \\:

    For example:

        rows = db.query(
            "SELECT * FROM table1 WHERE name = :name AND age >= :age",
            name="Joe",
            age=25)

    See sqlalchemy.text for details.

    Can execute on a specific connection by passing it as dbconn; if omitted, uses web.appdb.  (Note
    that dbconn *cannot* be used as a placeholder bind name).
    """

    if dbconn is None:
        from . import web

        dbconn = web.appdb

    return dbconn.execute(sqlalchemy.text(query), **params)


# Begins a (potentially nested) transaction.  Takes an optional connection; if omitted uses
# web.appdb.
def transaction(dbconn=None):
    if dbconn is None:
        from . import web

        dbconn = web.appdb
    return dbconn.begin_nested()


have_returning = True


def insert_and_get_pk(insert, pk, *, dbconn=None, **params):
    """
    Performs an insert and returns the value of the primary key by appending a RETURNING clause, if
    supported, and otherwise falling back to using .lastrowid.

    Takes the query, primary key column name, and any parameters to bind

    Can optionally take the database connection by passing as a dbconn parameter (note that you may
    not use "dbconn" as a bind parameter).  If omitted uses web.appdb.
    """

    if have_returning:
        insert += f" RETURNING {pk}"

    result = query(insert, dbconn=dbconn, **params)
    if have_returning:
        return result.scalar_one()
    return result.lastrowid


def database_init():
    """
    Perform database initialization: constructs the schema, if necessary, and performs any required
    migrations.  This does so using its *own* database connection, and is intended to be called
    during initialization *before* forking happens during uwsgi startup.
    """

    global engine, metadata

    metadata.clear()
    metadata.reflect(bind=engine, views=True)

    conn = get_conn()

    if 'messages' not in metadata.tables:
        logging.warning("No database detected; creating new database schema")
        if engine.name == "sqlite":
            conn.connection.executescript(importlib.resources.read_text('sogs', 'schema.sqlite'))
        elif engine.name == "postgresql":
            cur = conn.connection.cursor()
            cur.execute(importlib.resources.read_text('sogs', 'schema.pgsql'))
            cur.close()
        else:
            err = f"Don't know how to create the database for {engine.name}"
            logging.critical(err)
            raise RuntimeError(err)

        metadata.clear()
        metadata.reflect(bind=engine, views=True)

    changes = False

    # Database migrations/updates/etc.
    for migrate in (
        migrate_v01x,
        add_new_columns,
        update_message_views,
        create_message_details_deleter,
        check_for_hacks,
    ):
        if migrate(conn):
            changes = True

    if changes:
        metadata.clear()
        metadata.reflect(bind=engine, views=True)

    # Make sure the system admin users exists
    create_admin_user(conn)


def migrate_v01x(conn):
    n_rooms = conn.execute("SELECT COUNT(*) FROM rooms").first()[0]

    # Migration from a v0.1.x database:
    if n_rooms > 0 or not os.path.exists("database.db"):
        return False

    logging.warning("No rooms found, but database.db exists; attempting migration")
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
    return True


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

    added = False

    for table, cols in new_table_cols.items():
        for name, definition in cols.items():
            if name not in metadata.tables[table].c:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                added = True

    return added


def update_message_views(conn):
    if engine.name != "sqlite":
        if any(x not in metadata.tables['message_metadata'].c for x in ('whisper_to', 'filtered')):
            conn.execute("DROP VIEW IF EXISTS message_metadata")
            conn.execute("DROP VIEW IF EXISTS message_details")
            conn.execute(
                """
CREATE VIEW message_details AS
SELECT messages.*, uposter.session_id, uwhisper.session_id AS whisper_to
    FROM messages
        JOIN users uposter ON messages."user" = uposter.id
        LEFT JOIN users uwhisper ON messages.whisper = uwhisper.id
"""
            )
            conn.execute(
                """
CREATE VIEW message_metadata AS
SELECT id, room, "user", session_id, posted, edited, updated, filtered, whisper_to,
        length(data) AS data_unpadded, data_size, length(signature) as signature_length
    FROM message_details
"""
            )

            return True

    return False


def create_message_details_deleter(conn):
    if engine.name == "sqlite":
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

    return False  # No need to refresh metadata even if we added the trigger above.


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
    if 'file_id_hacks' in metadata.tables:
        # If the table exists but is empty (i.e. because all the attachments expired) then we should
        # drop it.
        n_fid_hacks = conn.execute("SELECT COUNT(*) FROM file_id_hacks").first()[0]
        if n_fid_hacks == 0:
            metadata.tables['file_id_hacks'].drop(engine)
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


def create_admin_user(dbconn):
    """
    We create a dummy user (with id 0) for system tasks such as changing moderators from
    command-line, and give it the server's x25519 pubkey (with ff prepended, *not* 05) as a fake
    default session_id.
    """
    query(
        """
        INSERT INTO users (id, session_id, moderator, admin, visible_mod)
            VALUES (0, :sid, TRUE, TRUE, FALSE)
        ON CONFLICT (id) DO UPDATE
            SET session_id = :sid, moderator = TRUE, admin = TRUE, visible_mod = FALSE
        """,
        sid="ff" + crypto.server_pubkey_hex,
        dbconn=dbconn,
    )


if config.DB_URL.startswith('postgresql'):
    # room.token is a 'citext' (case-insensitive text), which sqlalchemy doesn't recognize out of
    # the box.  Map it to a plain TEXT which is good enough for what we need (if we actually needed
    # to generate this wouldn't suffice: we'd have to use something like the sqlalchemy-citext
    # module).
    from sqlalchemy.dialects.postgresql.base import ischema_names

    if 'citext' not in ischema_names:
        ischema_names['citext'] = ischema_names['text']


engine, engine_initial_pid, metadata = None, None, None


def _init_engine(*args, **kwargs):
    """
    Initializes or reinitializes db.engine.  (Only the test suite should be calling this externally
    to reinitialize).
    """
    global engine, engine_initial_pid, metadata, have_returning

    if engine is not None:
        engine.dispose()

    if not len(args) and not len(kwargs):
        if config.DB_URL == 'defer-init':
            return
        args = (config.DB_URL,)

    # Disable *sqlalchemy*-level autocommit, which works so badly that it got completely removed in
    # 2.0.  (We put the actual sqlite into driver-level autocommit mode below).
    engine = sqlalchemy.create_engine(*args, **kwargs).execution_options(autocommit=False)
    engine_initial_pid = os.getpid()
    metadata = sqlalchemy.MetaData()

    if engine.name == "sqlite":
        import sqlite3

        have_returning = sqlite3.sqlite_version_info >= (3, 35, 0)

        @sqlalchemy.event.listens_for(engine, "connect")
        def sqlite_fix_connect(dbapi_connection, connection_record):
            # disable pysqlite's emitting of the BEGIN statement entirely.
            # also stops it from emitting COMMIT before any DDL.
            dbapi_connection.isolation_level = None

        @sqlalchemy.event.listens_for(engine, "begin")
        def do_begin(conn):
            # emit our own BEGIN
            conn.execute("BEGIN IMMEDIATE")

    else:
        have_returning = True

    database_init()


_init_engine()


@postfork
def reset_db_postfork():
    """Clear any connections from the engine after forking because they aren't shareable."""
    if engine is None or os.getpid() == engine_initial_pid:
        return
    engine.dispose()
