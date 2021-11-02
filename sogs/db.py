from . import config
import os
import sqlite3
from .postfork import postfork


# FIXME/TODO:
# - if the tables don't exist (e.g. room) then we should also init
# - if the *old* table structure exists we should migrate (there is rust code that does this that
#   needs to be converted).
_should_init = config.DB_PATH != ':memory:' and not os.path.exists(config.DB_PATH)

# initialize database as needed
if _should_init:
    with open(config.DB_SCHEMA_FILE) as f, sqlite3.connect(config.DB_PATH) as conn:
        conn.executescript(f.read())


conn = None
@postfork
def sqlite_connect():
    global conn
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
