#!/bin/bash

if ! [ -f contrib/upgrade-tests/common.sh ]; then
    echo "Wrong path: run from top-level sogs" >&2
    exit 1
fi

. contrib/upgrade-tests/common.sh

set -o errexit

for tag in "$@"; do
    if ! git rev-parse "$tag" >/dev/null; then
        echo "'$tag' doesn't look like a valid known git revision or tag!"
        exit 1
    fi
done

# Extract the SOGS 0.1.10 test database:
if ! [ -f test-sogs-0-1-10.tar.xz ]; then
    curl -sSOL https://oxen.rocks/test-sogs-0-1-10.tar.xz
fi

tar xf test-sogs-0-1-10.tar.xz

# Update the timestamps to be relatively current (so that we are importing files that shouldn't be
# expired):
for roomdb in rooms/*.db; do
    sqlite3 $roomdb "update files set timestamp = timestamp - 1645500000 + cast(((julianday('now') - 2440587.5)*86400.0) AS INTEGER)"
done

first=1

fixed_updates_count=

tags=("$@" "$(git rev-parse HEAD)")
for tag in "${tags[@]}"; do
    echo "Upgrading to $tag..."
    git -c advice.detachedHead=false checkout "$tag"

    args=("-L")

    if [ -n "$first" ]; then
        first=
        python3 -msogs.key_convert

        echo "Checking key_x25519 for proper conversion"
        diff --color=always \
            <(python3 -c 'f = open("key_x25519", "rb"); print(f.read().hex())') \
            <(echo a0101f8bca7fa1cedf9620f5b80810b18f5b0f1acbb219640876be9d78a6195f)

        # In 0.2.0 and up until close to 0.3.0, just running any command-line commands will do the
        # database import and/or upgrade.  Starting in 0.3.0 you have to specify --initialize to make
        # this happen.
        if [ -e sogs/__main__.py ] && grep -q '^ *"--initialize",$' sogs/__main__.py; then
            args+=("--initialize")
        fi
    fi

    python3 -msogs "${args[@]}"

    if [ -z "$fixed_over_updates" ]; then
        # 0.2.0 had a bug in one of the room update triggers that would unnecessarily update
        # `message_sequence` (then named `updates`) on metadata updates, which the import triggered
        # when setting the image value.  This was fixed before v0.3.0, but if we are testing an
        # import via such a problematic version then we need to undo the increment so that the final
        # message_sequence value remains comparable to a version that imported directly into a newer
        # release.
        if sed -ne '/^CREATE TRIGGER room_metadata_update/,/^END;/p' sogs/schema.sql* \
            | grep -q 'SET updates = updates + 1'; then
            sqlite3 sogs.db 'UPDATE rooms SET updates = updates - 1 WHERE image IS NOT NULL'
        fi
        fixed_updates_count=1
    fi
done
