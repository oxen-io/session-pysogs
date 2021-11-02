from . import config
import os
import sqlite3


# FIXME/TODO:
# - if the tables don't exist (e.g. room) then we should also init
# - if the *old* table structure exists we should migrate (there is rust code that does this that
#   needs to be converted).
_should_init = config.DB_PATH != ':memory:' and not os.path.exists(config.DB_PATH)
pool = sqlite3.Connection(config.DB_PATH)
pool.row_factory = sqlite3.Row

# initialize database as needed
if _should_init:
    with open(config.DB_SCHEMA_FILE) as f:
        with pool:
            pool.executescript(f.read())
