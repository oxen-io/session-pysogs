#!/usr/bin/env python3

# Script to copy an sqlite database into a postgresql database.  To fully do this with sogs:
# - stop sogs
# - run this script
# - update the sogs.ini to change the db to postgres
# - start sogs
#
# This operation is not currently reversible, this script is only ocassionally tested and may be
# outdated, and you should not do this unless you know what you are doing.

import psycopg
import sqlite3
import importlib.resources
import sys
import re
import time

import sogs  # noqa: F401


from argparse import ArgumentParser as AP

ap = AP()

ap.add_argument(
    '--drop-tables',
    action='store_true',
    help="drop current postgresql tables and recreate the database schema.  This is *required* but"
    " is an option so that you realize it's going to happen.",
)
ap.add_argument(
    '--commit',
    action='store_true',
    help="actually commit the import (without this the overall transaction is aborted)",
)
ap.add_argument('sogs_db', type=str, nargs=1, help='SQLite database filename to import from')
ap.add_argument('postgresql_url', type=str, nargs=1, help='Postgresql database URL to import to')

args = ap.parse_args()

print(args.sogs_db)
print(args.postgresql_url)

if not args.drop_tables:
    print("Cannot import without dropping tables, be careful!", file=sys.stderr)
    sys.exit(1)

pg_schema = importlib.resources.read_text('sogs', 'schema.pgsql')

TABLES = [
    "rooms",
    "users",
    "messages",
    "message_history",
    "pinned_messages",
    "reactions",
    "user_reactions",
    "files",
    "room_users",
    "user_permission_overrides",
    "user_permission_futures",
    "user_ban_futures",
    "user_request_nonces",
    "inbox",
    "needs_blinding",
]

import_tables = set(TABLES)
schema_tables = set(re.findall(r'^CREATE TABLE (\w+)', pg_schema, re.M))
if schema_tables != import_tables:
    print("Error: pg-import script table mismatch:", file=sys.stderr)
    missing_here = import_tables - schema_tables
    missing_there = schema_tables - import_tables
    if missing_here:
        print(f"Not in schema: {' '.join(missing_here)}", file=sys.stderr)
    if missing_there:
        print(f"Not in import: {' '.join(missing_there)}", file=sys.stderr)
    sys.exit(1)


old = sqlite3.connect(f"file:{args.sogs_db[0]}?mode=ro", uri=True)
old.row_factory = sqlite3.Row

pgsql = psycopg.connect(args.postgresql_url[0], autocommit=True)


with pgsql.transaction():
    curin = old.cursor()
    curout = pgsql.cursor()

    for t in ('file_id_hacks', 'room_import_hacks'):
        if curin.execute(f"SELECT COUNT(*) FROM sqlite_master WHERE name = '{t}'").fetchone()[0]:
            TABLES.append(t)

    pg_schema = re.sub(r'(?m)^BEGIN;$', '', pg_schema, count=1)
    pg_schema = re.sub(r'(?m)^COMMIT;$', '', pg_schema, count=1)
    for t in TABLES:
        curout.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    for t in ('file_id_hacks', 'room_import_hacks'):
        if t not in TABLES:
            curout.execute(f"DROP TABLE IF EXISTS {t} CASCADE")

    curout.execute(pg_schema)

    if 'file_id_hacks' in TABLES:
        curout.execute(
            """
            CREATE TABLE IF NOT EXISTS file_id_hacks (
                room BIGINT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                old_file_id BIGINT NOT NULL,
                file BIGINT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                PRIMARY KEY(room, old_file_id)
            )
            """
        )

    if 'room_import_hacks' in TABLES:
        curout.execute(
            """
            CREATE TABLE IF NOT EXISTS room_import_hacks (
                room BIGINT PRIMARY KEY NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                old_message_id_max BIGINT NOT NULL,
                message_id_offset BIGINT NOT NULL
            )
            """
        )

    # We have circular foreign keys that we need to break for the copy to work:
    curout.execute("ALTER TABLE rooms DROP CONSTRAINT room_image_fk")

    def copy(table):
        cols = [r['name'] for r in curin.execute(f"PRAGMA table_info({table})")]
        if not cols:
            raise RuntimeError(f"Expected table {table} does not exist in sqlite db")

        pg_types = {
            r[0]: r[1]
            for r in curout.execute(
                "SELECT column_name, data_type FROM information_schema.columns"
                " WHERE table_name = %s",
                (table,),
            )
        }
        if not pg_types:
            raise RuntimeError(f"Expected table {table} does not exist in pgsql")

        missing_out = set(cols).difference(pg_types.keys())
        missing_in = set(pg_types.keys()).difference(cols)
        if missing_in or missing_out:
            raise RuntimeError(
                f"Error: column mismatch for table {table}: "
                f"PG is missing {missing_out}; sqlite is missing {missing_in}"
            )

        count = 0
        count_total = curin.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"Importing {table}: {count}/{count_total}", end="", flush=True)
        started = time.time()
        for row in curin.execute(f"SELECT * FROM {table}"):
            colnames = ', '.join('"' + c + '"' if c == "user" else c for c in cols)
            vals = ', '.join('%s' for _ in cols)
            curout.execute(
                f"INSERT INTO {table} ({colnames}) VALUES ({vals})",
                [
                    bool(row[c]) if pg_types[c] == 'boolean' and row[c] in (0, 1) else row[c]
                    for c in cols
                ],
            )
            count += 1

            if count % 10 == 0 and args.commit:
                curout.execute("COMMIT; BEGIN")
            if count % 1000 == 0:
                print(f"\rImporting {table}: {count}/{count_total}", end="", flush=True)

        if args.commit:
            curout.execute("COMMIT; BEGIN")
        print(
            f"\rFinished importing {table}: {count}/{count_total} rows imported "
            f"[{time.time() - started:.3f}s]",
            flush=True,
        )

    for t in TABLES:
        copy(t)

    # Put the foreign key we deleted back in:
    print("Reactivating room_image foreign key...", end="", flush=True)
    started = time.time()
    curout.execute(
        "ALTER TABLE rooms ADD CONSTRAINT room_image_fk FOREIGN KEY (image)"
        " REFERENCES files ON DELETE SET NULL"
    )
    if args.commit:
        curout.execute("COMMIT; BEGIN")
    print(f" done [{time.time() - started:.3f}s].")

    # Our DB triggers mess with the seqno/updates values, so restore them:
    print("Updating message sequence counters...", end="", flush=True)
    started = time.time()
    count = 0
    count_total = curin.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    for mid, seqno, sdata, sreact, screat in curin.execute(
        "SELECT id, seqno, seqno_data, seqno_reactions, seqno_creation FROM messages"
    ):
        curout.execute(
            "UPDATE messages SET"
            " seqno = %(seqno)s,"
            " seqno_data = %(sdata)s,"
            " seqno_reactions = %(sreact)s,"
            " seqno_creation = %(screat)s "
            "WHERE id = %(id)s",
            {'id': mid, 'seqno': seqno, 'sdata': sdata, 'sreact': sreact, 'screat': screat},
        )
        count += 1
        if count % 1000 == 0:
            if args.commit:
                curout.execute("COMMIT; BEGIN")
            print(
                f"\rUpdating message sequence counters... {count}/{count_total}", end="", flush=True
            )
    if args.commit:
        curout.execute("COMMIT; BEGIN")
    print(
        f"\rUpdated message sequence counters... {count}/{count_total} "
        f"[{time.time() - started:.3f}s]",
        flush=True,
    )

    print("Updating room sequence/updates counters...")
    started = time.time()
    for row in curin.execute("SELECT id, message_sequence, info_updates FROM rooms"):
        curout.execute(
            "UPDATE rooms SET message_sequence = %s, info_updates = %s WHERE id = %s",
            [row[1], row[2], row[0]],
        )
    print(f" done [{time.time() - started:.3f}s].")

    # Restart the identity sequences (otherwise new inserts will fail with conflicting ids)
    print("Restarting identity sequences...", end="", flush=True)
    started = time.time()
    identities = [
        (r[0], r[1])
        for r in curout.execute(
            "SELECT table_name, column_name from information_schema.columns"
            " WHERE is_identity = 'YES'"
        )
    ]
    for table, col in identities:
        next_id = curout.execute(f"SELECT MAX({col}) FROM {table}").fetchone()[0]
        if next_id is not None:
            print(f" {table}.{col}={next_id+1}", end="", flush=True)
            curout.execute(f"ALTER TABLE {table} ALTER COLUMN {col} RESTART WITH {next_id+1}")
    print(f". Done [{time.time() - started:.3f}s].")

    if not args.commit:
        print("Import finished, aborting transaction (because --commit not given)")
        raise psycopg.Rollback()
