
set -o errexit

if [ "$1" != "--delete-my-crap" ]; then
    echo "
Warning: this script removes current database, files, and settings, and so should never be run on a
live installation.

Run with argument --delete-my-crap if that sounds okay" >&2

    exit 1
fi

shift

if ! [ -d contrib/upgrade-tests ] || ! [ -e sogs/__init__.py ]; then
    echo "You need to run this as ./contrib/upgrade-test.sh from the top-level sogs directory" >&2
    exit 1
fi

export PYTHONPATH=.

rm -rf rooms database.db files key_x25519 x25519_{public,private}_key.pem

echo -e "[log]\nlevel = DEBUG" >sogs.ini
if [ -n "$SOGS_PGSQL" ]; then
    echo -e "[db]\nurl = $SOGS_PGSQL" >>sogs.ini
    for table in rooms users messages message_history pinned_messages files room_users \
        user_permission_overrides user_permission_futures user_ban_futures user_request_nonces \
        inbox room_import_hacks file_id_hacks; do
        echo "DROP TABLE IF EXISTS $table CASCADE;"
    done | psql "$SOGS_PGSQL"
else
    rm -f sogs.db{,-shm,-wal}
fi
