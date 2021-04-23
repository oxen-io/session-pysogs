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

    /// Path to the log file. If not provided, logs are only printed to stdout.
    #[structopt(long = "log-file")]
    pub log_file: Option<String>,

    /// Run in TLS mode.
    #[structopt(long = "tls")]
    pub tls: bool,

    /// Path to TLS certificate.
    #[structopt(long = "tls-certificate", default_value = "tls_certificate.pem")]
    pub tls_certificate: String,

    /// Path to TLS private key.
    #[structopt(long = "tls-private-key", default_value = "tls_private_key.pem")]
    pub tls_private_key: String,

    /// Add a room with the given ID and name.
    #[structopt(long = "add-room")]
    pub add_room: Option<Vec<String>>,

    /// Deletes the room with the given ID.
    #[structopt(long = "delete-room")]
    pub delete_room: Option<String>,

    /// Makes the given public key a moderator for the room with the given ID.
    #[structopt(long = "add-moderator")]
    pub add_moderator: Option<Vec<String>>,

    /// Removes moderator permission for the given public key in the room with the given ID.
    #[structopt(long = "delete-moderator")]
    pub delete_moderator: Option<Vec<String>>,

    /// Prints the URL format users can use to join rooms on this open group server.
    #[structopt(long = "print-url")]
    pub print_url: bool,
}
