#!/bin/bash

if ! [ -f contrib/upgrade-tests/common.sh ]; then
    echo "Wrong path: run from top-level sogs" >&2
    exit 1
fi

if [ -n "$SOGS_PGSQL" ]; then
    echo "Error: SOGS_PGSQL is not supported for the v0.2.0 upgrade" >&2
    exit 1
fi

. contrib/upgrade-tests/common.sh

set -o errexit

# Extract the SOGS 0.2.0 test database:
if ! [ -f test-sogs-0-2-0.tar.xz ]; then
    curl -sSOL https://oxen.rocks/test-sogs-0-2-0.tar.xz
fi

tar xf test-sogs-0-2-0.tar.xz

# Update the timestamps to be relatively current (so that files aren't expired)
sqlite3 sogs.db <<SQL
UPDATE files SET uploaded = uploaded - 1646082000 + ((julianday('now') - 2440587.5)*86400.0),
    expiry = expiry - 1646082000 + ((julianday('now') - 2440587.5)*86400.0)
WHERE expiry IS NOT NULL;
SQL

do_upgrades "$@"
