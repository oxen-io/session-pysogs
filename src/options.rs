use std::net::Ipv4Addr;

use structopt::StructOpt;

// The default is * not * to run in TLS mode. This is because normally the server communicates through
// onion requests, eliminating the need for TLS.

#[derive(StructOpt)]
#[structopt(name = "Session Open Group Server")]
pub struct Opt {
    /// Path to X25519 public key.
    #[structopt(long = "x25519-public-key", default_value = "x25519_public_key.pem")]
    pub x25519_public_key: String,

    /// Path to X25519 private key.
    #[structopt(long = "x25519-private-key", default_value = "x25519_private_key.pem")]
    pub x25519_private_key: String,

    /// Port to bind to.
    #[structopt(short = "P", long = "port", default_value = "80")]
    pub port: u16,

    /// IP to bind to.
    #[structopt(short = "H", long = "host", default_value = "0.0.0.0")]
    pub host: Ipv4Addr,

    /// Run in TLS mode.
    #[structopt(long)]
    pub tls: bool,

    /// Path to TLS certificate.
    #[structopt(long = "tls-certificate", default_value = "tls_certificate.pem")]
    pub tls_certificate: String,

    /// Path to TLS private key.
    #[structopt(long = "tls-private-key", default_value = "tls_private_key.pem")]
    pub tls_private_key: String,
}
