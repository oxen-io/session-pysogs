from . import config
import os
import sqlite3


_should_init = config.DB_PATH != ':memory:' and not os.path.exists(config.DB_PATH)
pool = sqlite3.Connection(config.DB_PATH)

# initialize database as needed
if _should_init:
    with open(config.DB_SCHEMA_FILE) as f:
        with pool:
            pool.executescript(f.read())
