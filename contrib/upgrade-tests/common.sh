
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

        # Use the dedicated --upgrade command if it has been added in this revision:
        if [ -e sogs/__main__.py ] && grep -q '^ *"--upgrade",$' sogs/__main__.py; then
            args=("--upgrade")
        else
            # Before it was added, any command would implicitly upgrade:
            args=("-L")
        fi

        if [ -n "$sogs_need_initialize" ]; then
            sogs_need_initialize=

            if [ -n "$sogs_key_conv" ]; then
                python3 -msogs.key_convert

                echo "Checking key_x25519 for proper conversion"
                diff --color=always \
                    <(python3 -c 'f = open("key_x25519", "rb"); print(f.read().hex())') \
                    <(echo a0101f8bca7fa1cedf9620f5b80810b18f5b0f1acbb219640876be9d78a6195f)
            fi

            # In 0.2.0 and up until close to 0.3.0, just running any command-line commands will do the
            # database import and/or upgrade.  Starting in 0.3.0 you have to specify --initialize to make
            # this happen.
            if [ -e sogs/__main__.py ] && grep -q '^ *"--initialize",$' sogs/__main__.py; then
                if [ "${args[0]}" == "--upgrade" ]; then
                    # If we support the --upgrade flag then --initialize and --upgrade are exclusive:
                    args=("--initialize")
                else
                    args+=("--initialize")
                fi
            fi
        fi

        python3 -msogs "${args[@]}"

        if [ -n "$sogs_fix_updates_count" ]; then
            # 0.2.0 had a bug in one of the room update triggers that would unnecessarily update
            # `message_sequence` (then named `updates`) on metadata updates, which the 0.1.x import
            # triggered when setting the image value.  This was fixed before v0.3.0, but if our
            # first tag imports via such a problematic version then we need to undo the increment so
            # that the final message_sequence value remains comparable to a version that imported
            # directly into a newer release.
            if sed -ne '/^CREATE TRIGGER room_metadata_update/,/^END;/p' sogs/schema.sql* \
                | grep -q 'SET updates = updates + 1'; then
                sqlite3 sogs.db 'UPDATE rooms SET updates = updates - 1 WHERE image IS NOT NULL'
            fi
            sogs_fix_updates_count=
        fi
    done

    # This should exit cleanly to indicate no needed migrations (if it doesn't, i.e. we still
    # require migrations after doing a migration then Something Getting Wrong in migrations).
    python3 -msogs --check-upgrades

    # Run the cleanup job to make sure we have the proper rooms.active_users values
    python3 -c 'from sogs.cleanup import cleanup; cleanup()'
}
