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

The Linux Rust installer assumes that you already have a C linker installed. If this is not the case you'll see `error: linker 'cc' not found`. To fix this, run:

```
sudo apt update
sudo apt upgrade
sudo apt install build-essential libssl-dev pkg-config
```

Build it with

```
cargo build --release
```

### Step 3: Run it
The two files generated in step 1 should be copied to the same directory as the executable. Alternatively you can use the command line arguments below to specify their locations. The executable needs both the x25519-public-key and the x25519-private-key to run.

```
./target/release/session-open-group-server
```

**Command line arguments:**

| Command            | Default                | Description                                                             |
| ------------------ |:----------------------:| ----------------------------------------------------------------------- |
| x25519-public-key  | x25519_public_key.pem  | Path to X25519 public key                                               |
| x25519-private-key | x25519_private_key.pem | Path to X25519 private key                                              |
| port               | 80                     | Port to bind to                                                         |
| host               | 0.0.0.0                | IP to bind to                                                           |
| log-file           | None                   | Path to the log file. If not provided, logs are only printed to stdout. |

If you want to run with TLS enabled:

| Command         | Default             | Description             |
| --------------- |:-------------------:| ----------------------- |
| tls             | false               | Run in TLS mode         |
| tls-certificate | tls_certificate.pem | Path to TLS certificate |
| tls-private-key | tls_private_key.pem | Path to TLS private key |

Note that the default is * not * to run in TLS mode. This is because normally the server communicates through [onion requests](https://arxiv.org/pdf/2002.04609.pdf), eliminating the need for TLS.

## Building a DEB

To build a DEB, just run `cargo deb` from the project root directory. If you don't yet have `cargo-deb` installed you can get it by running: `cargo install cargo-deb`.
