use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::join;
use structopt::StructOpt;
use tokio;
use warp::Filter;

mod crypto;
mod errors;
mod handlers;
mod logging;
mod models;
mod onion_requests;
mod routes;
mod rpc;
mod storage;

use log::info;

#[cfg(test)]
mod tests;

// The default is * not * to run in TLS mode. This is because normally the server communicates through
// onion requests, eliminating the need for TLS.

#[derive(StructOpt)]
#[structopt(name = "Session Open Group Server")]
struct Opt {
    /// Run in TLS mode.
    #[structopt(long)]
    tls: bool,

    /// Path to TLS certificate.
    #[structopt(long = "tls-certificate", default_value = "tls_certificate.pem")]
    tls_certificate: String,

    /// Path to TLS private key.
    #[structopt(long = "tls-private-key", default_value = "tls_private_key.pem")]
    tls_private_key: String,

    /// Path to X25519 public key.
    #[structopt(long = "x25519-public-key", default_value = "x25519_public_key.pem")]
    x25519_public_key: String,

    /// Path to X25519 private key.
    #[structopt(long = "x25519-private-key", default_value = "x25519_private_key.pem")]
    x25519_private_key: String,

    /// Path to the file where logs will be saved. If not provided, logs are only
    /// printed to stdout.
    #[structopt(long = "log-file")]
    log_file: Option<String>,

    /// Port to bind to.
    #[structopt(short = "P", long = "port", default_value = "80")]
    port: u16,

    /// IP to bind to.
    #[structopt(short = "H", long = "host", default_value = "0.0.0.0")]
    host: Ipv4Addr
}

#[tokio::main]
async fn main() {
    // Parse arguments
    let opt = Opt::from_args();

    logging::init(opt.log_file);

    let addr = SocketAddr::new(IpAddr::V4(opt.host), opt.port);
    *crypto::PRIVATE_KEY_PATH.lock().unwrap() = opt.x25519_private_key;
    *crypto::PUBLIC_KEY_PATH.lock().unwrap() = opt.x25519_public_key;
    // Print the server public key
    let hex_public_key = hex::encode(crypto::PUBLIC_KEY.as_bytes());
    info!("The public key of this server is: {}", hex_public_key);
    // Create the main database
    storage::create_main_database_if_needed();
    // Create required folders
    fs::create_dir_all("./rooms").unwrap();
    fs::create_dir_all("./files").unwrap();
    // Create default rooms
    create_default_rooms().await;
    // Set up pruning jobs
    let prune_pending_tokens_future = storage::prune_pending_tokens_periodically();
    let prune_tokens_future = storage::prune_tokens_periodically();
    let prune_files_future = storage::prune_files_periodically();
    // Serve routes
    let routes = routes::root().or(routes::lsrpc());
    if opt.tls {
        info!("Running on {} with TLS.", addr);
        let serve_routes_future = warp::serve(routes)
            .tls()
            .cert_path(opt.tls_certificate)
            .key_path(opt.tls_private_key)
            .run(addr);
        // Keep futures alive
        join!(
            prune_pending_tokens_future,
            prune_tokens_future,
            prune_files_future,
            serve_routes_future
        );
    } else {
        info!("Running on {}.", addr);
        let serve_routes_future = warp::serve(routes).run(addr);
        // Keep futures alive
        join!(
            prune_pending_tokens_future,
            prune_tokens_future,
            prune_files_future,
            serve_routes_future
        );
    }
}

async fn create_default_rooms() {
    let info: Vec<(&str, &str)> = vec![("main", "Main")];
    for info in info {
        let id = info.0;
        let name = info.1;
        handlers::create_room(id, name).await.unwrap();
    }
}
