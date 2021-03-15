#!/bin/bash
$ echo checking that rust, git and openssl are installed...

# Check that rustup, git and openssl are installed
$ type rustup >/dev/null 2>&1 || { echo >&2 "rustup not found; make sure it's installed."; exit 1; }
$ type git >/dev/null 2>&1 || { echo >&2 "git not found; make sure it's installed."; exit 1; }
$ type openssl >/dev/null 2>&1 || { echo >&2 "openssl not found; make sure it's installed."; exit 1; }

# TODO: Check openssl version

# Clone the repo
git clone git@github.com:nielsandriesse/session-open-group-server.git

# Generate a key pair
openssl genpkey -algorithm x25519 -out session-open-group-server/x25519_private_key.pem
openssl pkey -in session-open-group-server/x25519_private_key.pem -pubout -out session-open-group-server/x25519_public_key.pem

# Build
cargo build

# TODO: linking with `cc` failed
