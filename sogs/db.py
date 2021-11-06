from . import config
from .postfork import postfork
import os
import sqlite3
import logging


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

    conn.close()


database_init()

conn = None


@postfork
def sqlite_connect_postfork():
    """
    Establishes a new sqlite per-process database connection after wsgi forks us.
    """
    global conn
    conn = sqlite_connect()
