#!/bin/bash

set -e

if ! [ -e "sogs/__init__.py" ]; then
    echo "Error: must run this from the session-pysogs root directory" >&2
    exit 1
fi

protos=(session.proto)

tmp=$(mktemp -d protobuf.XXXXXXXX)
cd $tmp
mkdir sogs
for proto in "${protos[@]}"; do
    ln -s "../../sogs/static/$proto" "sogs/$proto"
done

protoc --python_out . sogs/*.proto

for proto in "${protos[@]}"; do
    pb2_py="${proto/-/_}"
    pb2_py="sogs/${pb2_py/.proto/}_pb2.py"
    if cmp -s $pb2_py ../$pb2_py; then
        rm -f $pb2_py
        echo "$pb2_py unchanged"
    else
        mv -f $pb2_py ../sogs/
        echo "$pb2_py updated"
    fi
    rm sogs/$proto
done

rmdir sogs
cd ..
rmdir $tmp
