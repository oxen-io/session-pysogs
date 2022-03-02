import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """
    New columns that might need to be added that don't require more complex migrations beyond simply
    adding the column.
    """

    from .. import db

    new_table_cols = {
        'messages': {
            'whisper': 'INTEGER REFERENCES users(id)',
            'whisper_mods': 'BOOLEAN NOT NULL DEFAULT FALSE',
            'filtered': 'BOOLEAN NOT NULL DEFAULT FALSE',
        }
    }

    added = False

    for table, cols in new_table_cols.items():
        for name, definition in cols.items():
            if name not in db.metadata.tables[table].c:
                logging.warning(f"DB migration: Adding new column {table}.{name}")
                if check_only:
                    raise DatabaseUpgradeRequired(f"new column {table}.{name}")
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                added = True

    return added
