#!/bin/bash

if ! [ -f contrib/upgrade-tests/common.sh ]; then
    echo "Wrong path: run from top-level sogs" >&2
    exit 1
fi

if [ -z "$SOGS_PGSQL" ]; then
    echo "Error: must specify pg url via SOGS_PGSQL env variable" >&2
    exit 1
fi

. contrib/upgrade-tests/common.sh

set -o errexit

# Extract the SOGS 0.3.0 postgresql test database:
if ! [ -f test-sogs-pg-f6dd80c04b.tar.xz ]; then
    curl -sSOL https://oxen.rocks/sogs-assets/test-sogs-pg-f6dd80c04b.tar.xz
fi

tar xf test-sogs-pg-f6dd80c04b.tar.xz

psql -f sogstest.pgsql "$SOGS_PGSQL"

# Update the timestamps to be relatively current (so that files aren't expired)
psql "$SOGS_PGSQL" <<SQL
UPDATE files SET uploaded = uploaded - 1646082000 + extract(epoch from now()),
    expiry = expiry - 1646082000 + extract(epoch from now())
WHERE expiry IS NOT NULL
SQL

do_upgrades "$@"
