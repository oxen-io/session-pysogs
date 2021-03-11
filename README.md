
### Step 1: Generating an X25519 key pair for your open group server

To generate an X25519 key pair, simply run:

```
openssl genpkey -algorithm x25519 -out x25519_private_key.pem
openssl pkey -in x25519_private_key.pem -pubout -out x25519_public_key.pem
```

Make sure you have openssl installed, and make sure you're pointing to the right openssl installation as well (e.g. macOS provides an old default implementation that doesn't have the X25519 algorithm).

### Step 2: Building the project:

To build and run the project, do:

```
cargo build
cargo run
```
