
## Requirements

| Dependency    | Version       |
| ------------- |:-------------:|
| rustup        | 1.50.0        |
| openssl       | 1.1.1         |

## Setup

### Step 1: Generate an X25519 key pair

```
openssl genpkey -algorithm x25519 -out x25519_private_key.pem
openssl pkey -in x25519_private_key.pem -pubout -out x25519_public_key.pem
```

Make sure you're pointing to the right openssl installation (e.g. macOS provides an old default implementation that doesn't have the X25519 algorithm).

### Step 2: Generate an SSL certificate

```
apt install certbot // Only if you don't have certbot installed already
certbot certonly
```

Follow the instructions on-screen and then move the generated certificate and private key to the session-open-group-folder (you'll need to rename them to tls_private_key.pem and tls_certificate respectively as well).

### Step 3: Build the project

```
cargo build
```

The Linux Rust installer assumes that you already have a C linker installed. If this is not the case you'll see `error: linker 'cc' not found`. To fix this, run:

```
apt update
sudo apt install build-essential
```

### Step 4: Run it

```
cargo run --release
```
