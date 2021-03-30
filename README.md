![example workflow](https://github.com/nielsandriesse/session-open-group-server/actions/workflows/build.yml/badge.svg)

[Documentation](https://github.com/nielsandriesse/session-open-group-server/wiki/Documentation)

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

### Step 2: Build the project

```
cargo build --release
```

The Linux Rust installer assumes that you already have a C linker installed. If this is not the case you'll see `error: linker 'cc' not found`. To fix this, run:

```
apt update
sudo apt install build-essential
```

### Step 3: Run it

```
./target/release/session-open-group-server
```

**Command line arguments:**

| Command            | Default                | Description                |
| ------------------ |:----------------------:| -------------------------- |
| x25519-public-key  | x25519_public_key.pem  | Path to X25519 public key  |
| x25519-private-key | x25519_private_key.pem | Path to X25519 private key |
| port               | 80                     | Port to bind to            |
| host               | 0.0.0.0                | IP to bind to              |

If you want to run with TLS enabled:

| Command         | Default             | Description             |
| --------------- |:-------------------:| ----------------------- |
| tls             | false               | Run in TLS mode         |
| tls-certificate | tls_certificate.pem | Path to TLS certificate |
| tls-private-key | tls_private_key.pem | Path to TLS private key |

Note that the default is * not * to run in TLS mode. This is because normally the server communicates through [onion requests](https://arxiv.org/pdf/2002.04609.pdf), eliminating the need for TLS.
