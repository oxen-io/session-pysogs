from . import config
from . import crypto
from .postfork import postfork
import os
import logging
import importlib.resources
import sqlalchemy
from sqlalchemy.sql.expression import bindparam

HAVE_FILE_ID_HACKS = False
# roomid => (max, offset).  Max is the highest message id that was in the old table; offset is the
# value we add to ids <= that max to calculate the new database message id.
ROOM_IMPORT_HACKS = {}


def get_conn():
    """Gets a connection from the database engine connection pool.  This is not intended to be used
    by flask endpoints: they should use web.appdb instead (which calls this upon first use)."""
    return engine.connect()


def query(query, *, dbconn=None, bind_expanding=None, **params):
    """Executes a query containing :param style placeholders (regardless of the actual underlying
    database placeholder style), binding them using the given params keyword arguments.

    Note that, if the query contains a literal : it must be escaped as \\:

    For example:

        rows = db.query(
            "SELECT * FROM table1 WHERE name = :name AND age >= :age",
            name="Joe",
            age=25)

    See sqlalchemy.text for details.

    bind_expanding can be passed a sequence of bind names that are "expanding" to a tuple, most
    commonly used to bind and expand the RHS of a `x IN :x` clause.

    Can execute on a specific connection by passing it as dbconn; if omitted, uses web.appdb.  (Note
    that dbconn *cannot* be used as a placeholder bind name).
    """

    if dbconn is None:
        from . import web

        dbconn = web.appdb

    q = sqlalchemy.text(query)

    if bind_expanding:
        q = q.bindparams(*(bindparam(c, expanding=True) for c in bind_expanding))

    return dbconn.execute(q, **params)


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
        return result.first()[0]
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

        if 'messages' not in metadata.tables:
            msg = (
                "Critical error: SQL schema creation failed; "
                f"tables: {', '.join(metadata.tables.keys())}"
            )
            logging.critical(msg)
            raise RuntimeError(msg)

    changes = False

    # Database migrations/updates/etc.
    for migrate in (
        migrate_v01x,
        add_new_tables,
        add_new_columns,
        create_message_details_deleter,
        check_for_hacks,
        seqno_etc_updates,
        update_message_views,
        user_perm_future_updates,
    ):
        with transaction(conn):
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
    }

    added = False

    for table, cols in new_table_cols.items():
        for name, definition in cols.items():
            if name not in metadata.tables[table].c:
                logging.warning(f"DB migration: Adding new column {table}.{name}")
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                added = True

    return added


def add_new_tables(conn):
    added = False
    if 'user_request_nonces' not in metadata.tables:
        logging.warning("DB migration: Adding new table user_request_nonces")
        if engine.name == 'sqlite':
            conn.execute(
                """
CREATE TABLE user_request_nonces (
    user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nonce BLOB NOT NULL UNIQUE,
    expiry FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5 + 1.0)*86400.0) /* now + 24h */
)
"""
            )
            conn.execute("CREATE INDEX user_request_nonces_expiry ON user_request_nonces(expiry)")
        else:
            conn.execute(
                """
CREATE TABLE user_request_nonces (
    "user" BIGINT NOT NULL REFERENCES users ON DELETE CASCADE,
    nonce BYTEA NOT NULL UNIQUE,
    expiry FLOAT NOT NULL DEFAULT (extract(epoch from now() + '24 hours'))
)
"""
            )
            conn.execute("CREATE INDEX user_request_nonces_expiry ON user_request_nonces(expiry)")

        added = True

    return added


def update_message_views(conn):
    if engine.name == "sqlite":
        if any(x not in metadata.tables['message_metadata'].c for x in ('whisper_to', 'filtered')):
            logging.warning("DB migration: replacing message_metadata/message_details views")
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
CREATE TRIGGER message_details_deleter INSTEAD OF DELETE ON message_details
FOR EACH ROW WHEN OLD.data IS NOT NULL
BEGIN
    UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
        WHERE id = OLD.id;
END
"""
            )
            conn.execute(
                """
CREATE VIEW message_metadata AS
SELECT id, room, "user", session_id, posted, edited, seqno, filtered, whisper_to,
        length(data) AS data_unpadded, data_size, length(signature) as signature_length
    FROM message_details
"""
            )

            return True

    # else: don't worry about this for postgresql because initial pg support had the fix

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
            logging.warning("Dropping file_id_hacks old sogs import table (no longer required)")
            metadata.tables['file_id_hacks'].drop(engine)
        else:
            logging.warning("Keeping file_id_hacks old sogs import table (still required)")
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


def seqno_etc_updates(conn):
    """
    Rename rooms.updates/messages.updated to rooms.message_sequence/messages.seqno for better
    disambiguation with rooms.info_updates.

    This also does various other changes/fixes that came at the same time as the column rename:

    - remove "updated" from and add "pinned_by"/"pinned_at" to pinned_messages
    - recreate the pinned_messages table and triggers because we need several changes:
        - add trigger to unpin a message when the message is deleted
        - remove "updates" (now message_sequence) updates from room metadata update trigger
        - add AFTER UPDATE trigger to properly update room metadata counter when re-pinning an
          existing pinned message
    - fix user_permissions view to return true for read/write/upload to true for moderators
    """

    if 'seqno' in metadata.tables['messages'].c:
        return False

    logging.warning("Applying message_sequence renames")
    conn.execute("ALTER TABLE rooms RENAME COLUMN updates TO message_sequence")
    conn.execute("ALTER TABLE messages RENAME COLUMN updated TO seqno")

    # We can't insert the required pinned_messages because we don't have the pinned_by user, but
    # that isn't a big deal since we didn't have any endpoints for pinned messsages before this
    # anyway, so we just recreate the whole thing (along with triggers which we also need to
    # update/fix)
    logging.warning("Recreating pinned_messages table")
    conn.execute("DROP TABLE pinned_messages")
    if engine.name == 'sqlite':
        conn.execute(
            """
CREATE TABLE pinned_messages (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    pinned_by INTEGER NOT NULL REFERENCES users(id),
    pinned_at FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch when pinned */
    PRIMARY KEY(room, message)
)
"""  # noqa: E501
        )
        conn.execute(
            """
CREATE TRIGGER messages_after_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NULL AND OLD.data IS NOT NULL
BEGIN
    -- Unpin if we deleted a pinned message:
    DELETE FROM pinned_messages WHERE message = OLD.id;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_add AFTER INSERT ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = NEW.room;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_update AFTER UPDATE ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = NEW.room;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_remove AFTER DELETE ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = OLD.room;
END
"""
        )

        logging.warning("Fixing user_permissions view")
        conn.execute("DROP VIEW IF EXISTS user_permissions")
        conn.execute(
            """
CREATE VIEW user_permissions AS
SELECT
    rooms.id AS room,
    users.id AS user,
    users.session_id,
    CASE WHEN users.banned THEN TRUE ELSE COALESCE(user_permission_overrides.banned, FALSE) END AS banned,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.read, rooms.read) END AS read,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.write, rooms.write) END AS write,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.upload, rooms.upload) END AS upload,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.moderator, FALSE) END AS moderator,
    CASE WHEN users.admin THEN TRUE ELSE COALESCE(user_permission_overrides.admin, FALSE) END AS admin,
    -- room_moderator will be TRUE if the user is specifically listed as a moderator of the room
    COALESCE(user_permission_overrides.moderator OR user_permission_overrides.admin, FALSE) AS room_moderator,
    -- global_moderator will be TRUE if the user is a global moderator/admin (note that this is
    -- *not* exclusive of room_moderator: a moderator/admin could be listed in both).
    COALESCE(users.moderator OR users.admin, FALSE) as global_moderator,
    -- visible_mod will be TRUE if this mod is a publicly viewable moderator of the room
    CASE
        WHEN user_permission_overrides.moderator OR user_permission_overrides.admin THEN user_permission_overrides.visible_mod
        WHEN users.moderator OR users.admin THEN users.visible_mod
        ELSE FALSE
    END AS visible_mod
FROM
    users JOIN rooms LEFT OUTER JOIN user_permission_overrides ON
        users.id = user_permission_overrides.user AND rooms.id = user_permission_overrides.room
"""  # noqa: E501
        )

    else:  # postgresql
        logging.warning("Recreating pinned_messages table")
        conn.execute(
            """
CREATE TABLE pinned_messages (
    room BIGINT NOT NULL REFERENCES rooms ON DELETE CASCADE,
    message BIGINT NOT NULL REFERENCES messages ON DELETE CASCADE,
    pinned_by BIGINT NOT NULL REFERENCES users,
    pinned_at FLOAT NOT NULL DEFAULT (extract(epoch from now())),
    PRIMARY KEY(room, message)
);


-- Trigger to handle required updates after a message gets deleted (in the SOGS context: that is,
-- has data set to NULL)
CREATE OR REPLACE FUNCTION trigger_messages_after_delete()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    -- Unpin if we deleted a pinned message:
    DELETE FROM pinned_messages WHERE message = OLD.id;
    RETURN NULL;
END;$$;
CREATE TRIGGER messages_after_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN (NEW.data IS NULL AND OLD.data IS NOT NULL)
EXECUTE PROCEDURE trigger_messages_after_delete();

CREATE TRIGGER room_metadata_pinned_add AFTER INSERT OR UPDATE ON pinned_messages
FOR EACH ROW
EXECUTE PROCEDURE trigger_room_metadata_info_update_new();

CREATE TRIGGER room_metadata_pinned_remove AFTER DELETE ON pinned_messages
FOR EACH ROW
EXECUTE PROCEDURE trigger_room_metadata_info_update_old();
"""
        )

        logging.warning("Fixing user_permissions view")
        conn.execute(
            """
CREATE OR REPLACE VIEW user_permissions AS
SELECT
    rooms.id AS room,
    users.id AS "user",
    users.session_id,
    CASE WHEN users.banned THEN TRUE ELSE COALESCE(user_permission_overrides.banned, FALSE) END AS banned,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.read, rooms.read) END AS read,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.write, rooms.write) END AS write,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.upload, rooms.upload) END AS upload,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.moderator, FALSE) END AS moderator,
    CASE WHEN users.admin THEN TRUE ELSE COALESCE(user_permission_overrides.admin, FALSE) END AS admin,
    -- room_moderator will be TRUE if the user is specifically listed as a moderator of the room
    COALESCE(user_permission_overrides.moderator OR user_permission_overrides.admin, FALSE) AS room_moderator,
    -- global_moderator will be TRUE if the user is a global moderator/admin (note that this is
    -- *not* exclusive of room_moderator: a moderator/admin could be listed in both).
    COALESCE(users.moderator OR users.admin, FALSE) as global_moderator,
    -- visible_mod will be TRUE if this mod is a publicly viewable moderator of the room
    CASE
        WHEN user_permission_overrides.moderator OR user_permission_overrides.admin THEN user_permission_overrides.visible_mod
        WHEN users.moderator OR users.admin THEN users.visible_mod
        ELSE FALSE
    END AS visible_mod
FROM
    users CROSS JOIN rooms LEFT OUTER JOIN user_permission_overrides ON
        (users.id = user_permission_overrides."user" AND rooms.id = user_permission_overrides.room);
"""  # noqa: E501
        )

    return True


def user_perm_future_updates(conn):
    """
    Break up user_permission_futures to not be (room,user) unique, and to move ban futures to a
    separate table.
    """

    if 'user_ban_futures' in metadata.tables:
        return False

    logging.warning("Updating user_permission_futures")

    if engine.name == 'sqlite':
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

ALTER TABLE user_permission_futures DROP CONSTRAINT user_permission_futures_pkey;
ALTER TABLE user_permission_futures DROP COLUMN banned;
"""
        )

    return True


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


engine, engine_initial_pid, metadata = None, None, None


def _init_engine(*args, **kwargs):
    """
    Initializes or reinitializes db.engine.  (Only the test suite should be calling this externally
    to reinitialize).

    Arguments:
    sogs_preinit - a callable to invoke after setting up `engine` but before calling
    `database_init()`.
    """
    global engine, engine_initial_pid, metadata, have_returning

    if engine is not None:
        engine.dispose()

    if not len(args) and not len(kwargs):
        if config.DB_URL == 'defer-init':
            return
        args = (config.DB_URL,)

    preinit = kwargs.pop('sogs_preinit', None)

    exec_opts_args = {}
    if args[0].startswith('postgresql'):
        exec_opts_args['isolation_level'] = 'READ COMMITTED'
    else:
        # SQLite's Python code is seriously broken, so we have to force off autocommit mode and turn
        # on driver-level autocommit (which we do below).
        exec_opts_args['autocommit'] = False

    engine = sqlalchemy.create_engine(*args, **kwargs).execution_options(**exec_opts_args)
    engine_initial_pid = os.getpid()
    metadata = sqlalchemy.MetaData()

    if engine.name == "sqlite":
        import sqlite3

        if sqlite3.sqlite_version_info < (3, 25, 0):
            raise RuntimeError(
                f"SQLite3 library version {'.'.join(sqlite3.sqlite_version_info)} "
                "is too old for pysogs (3.25.0+ required)!"
            )

        have_returning = sqlite3.sqlite_version_info >= (3, 35, 0)

        @sqlalchemy.event.listens_for(engine, "connect")
        def sqlite_fix_connect(dbapi_connection, connection_record):
            # disable pysqlite's emitting of the BEGIN statement entirely.
            # also stops it from emitting COMMIT before any DDL.
            dbapi_connection.isolation_level = None
            # Enforce foreign keys.  It is very sad that this is not default.
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        @sqlalchemy.event.listens_for(engine, "begin")
        def do_begin(conn):
            # emit our own BEGIN
            conn.execute("BEGIN IMMEDIATE")

    else:
        have_returning = True

        # rooms.token is a 'citext' (case-insensitive text), which sqlalchemy doesn't recognize out
        # of the box.  Map it to a plain TEXT which is good enough for what we need (if we actually
        # needed to generate this wouldn't suffice: we'd have to use something like the
        # sqlalchemy-citext module).
        from sqlalchemy.dialects.postgresql.base import ischema_names

        if 'citext' not in ischema_names:
            ischema_names['citext'] = ischema_names['text']

    if preinit:
        preinit()

    database_init()


_init_engine()


@postfork
def reset_db_postfork():
    """Clear any connections from the engine after forking because they aren't shareable."""
    if engine is None or os.getpid() == engine_initial_pid:
        return
    engine.dispose()
