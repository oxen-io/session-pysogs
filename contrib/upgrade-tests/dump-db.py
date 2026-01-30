#!/usr/bin/env python3

from prettytable import PrettyTable
import time
import os

if 'SOGS_PGSQL' in os.environ and os.environ['SOGS_PGSQL']:
    try:
        import psycopg as pg

        conn = pg.connect(os.environ['SOGS_PGSQL'], autocommit=True)
    except ModuleNotFoundError:
        import psycopg2 as pg

        conn = pg.connect(os.environ['SOGS_PGSQL'])
        conn.autocommit = True
else:
    pg = None
    import sqlite3

    conn = sqlite3.connect('file:sogs.db?mode=ro', uri=True)

cur = conn.cursor()


# Sorting priorities for column names (because different import paths could end up with different
# column orders in the table when we `SELECT *`).  Lower = earlier.  Anything not in here gets a
# sort value of 100, and equal orders are sorted alphabetically.
column_priority = {
    'id': 0,
    'room': 1,
    'token': 2,
    'user': 3,
    'session_id': 4,
    'name': 4,
    'description': 5,
    'image': 6,
    'admin': 101,
    'moderator': 102,
    'global_moderator': 103,
    'room_moderator': 103,
    'visible_mod': 103,
    'read': 104,
    'accessible': 105,
    'write': 106,
    'upload': 107,
    'banned': 108,
}


def dump_rows(table, extra=None, where=None, order="id", skip=set()):
    print(f"{table}:")
    ob = order if isinstance(order, str) else ', '.join(order)
    extra = f', {extra}' if extra else ''
    cur.execute(f"SELECT * {extra} FROM {table} {'WHERE ' + where if where else ''} ORDER BY {ob}")
    cols = [x[0] for x in cur.description]

    indices = [i for i in range(len(cols)) if cols[i] not in skip]
    indices.sort(key=lambda i: (column_priority.get(cols[i], 100), cols[i]))

    table = PrettyTable()
    table.field_names = [cols[i] for i in indices]
    for r in cur:
        table.add_row(
            [
                (
                    'NULL'
                    if r[i] is None
                    else (
                        int(r[i])
                        if isinstance(r[i], bool)
                        else f"{r[i]:.3f}" if isinstance(r[i], float) else r[i]
                    )
                )
                for i in indices
            ]
        )
    for c in cols:
        table.align[c] = 'l' if c in ('token', 'name', 'session_id', 'description', 'path') else 'r'
    return table.get_string() + "\n"


print(dump_rows("rooms", skip={'created', 'info_updates'}))

TableNotFoundError = pg.errors.UndefinedTable if pg else sqlite3.OperationalError
try:
    print(dump_rows("room_import_hacks", order='room'))
except TableNotFoundError:
    pass

print(dump_rows("message_metadata"))

print(dump_rows("pinned_messages", order=("room", "pinned_at")))

print(
    dump_rows(
        "files",
        extra=f"CASE WHEN expiry IS NULL THEN NULL ELSE uploaded > {time.time()-86400} END "
        "AS recent_upload",
        skip={'uploaded', 'expiry'},
    )
)

try:
    print(dump_rows("file_id_hacks", order='file'))
except TableNotFoundError:
    pass

print(dump_rows("users", where="id != 0", skip={'created', 'last_active'}))

print(dump_rows("room_users", order=('room', '"user"')))

print(dump_rows("user_permissions", where='"user" != 0', order=('room', '"user"')))

print(dump_rows("inbox"))
