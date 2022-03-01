
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

for tag in "$@"; do
    if ! git rev-parse "$tag" >/dev/null; then
        echo "'$tag' doesn't look like a valid known git revision or tag!"
        exit 1
    fi
done


do_upgrades() {
    tags=("$@" "$(git rev-parse HEAD)")
    for tag in "${tags[@]}"; do
        echo "Upgrading to $tag..."
        git -c advice.detachedHead=false checkout "$tag"

        args=("-L")

        if [ -n "$first" ]; then
            first=

            # In 0.2.0 and up until close to 0.3.0, just running any command-line commands will do the
            # database import and/or upgrade.  Starting in 0.3.0 you have to specify --initialize to make
            # this happen.
            if [ -e sogs/__main__.py ] && grep -q '^ *"--initialize",$' sogs/__main__.py; then
                args+=("--initialize")
            fi
        fi

        python3 -msogs "${args[@]}"
    done
}
