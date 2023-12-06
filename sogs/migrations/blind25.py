import logging
from .exc import DatabaseUpgradeRequired
from sqlalchemy.schema import UniqueConstraint


def migrate(conn, *, check_only):
    """
    Drops the unique constraint from the "user" column of needs_blinding so that we can insert both
    15 and 25 blinded values for a single user.
    """

    from .. import db

    nb = db.metadata.tables['needs_blinding']
    usercol = nb.c['user']
    found = None
    for constr in nb.constraints:
        if isinstance(constr, UniqueConstraint) and constr.contains_column(usercol):
            found = constr
            break

    if found is None:
        return False

    logging.warning("DB migration: dropping UNIQUE constraint from needs_blinding.user")
    if db.engine.name == "sqlite":
        conn.execute("ALTER TABLE needs_blinding RENAME TO needs_blinding_old")
        conn.execute(
            """
CREATE TABLE needs_blinding (
    blinded_abs TEXT NOT NULL PRIMARY KEY, -- the positive of the possible two blinded keys
    "user" INTEGER NOT NULL REFERENCES users ON DELETE CASCADE
)
"""
        )
        conn.execute(
            'INSERT INTO needs_blinding SELECT blinded_abs, "user" FROM needs_blinding_old'
        )
        conn.execute('DROP TABLE needs_blinding_old')

    else:

        conn.execute(f"ALTER TABLE needs_blinding DROP CONSTRAINT {found.name}")

    return True
