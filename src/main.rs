use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::join;
use structopt::StructOpt;
use tokio;
use warp::Filter;

mod crypto;
mod errors;
mod handlers;
mod models;
mod onion_requests;
mod routes;
mod rpc;
mod storage;

#[cfg(test)]
mod tests;

#[derive(StructOpt)]
#[structopt(name = "Session Open Group Server")]
struct Opt {
    /// Run in plaintext mode for use behind a reverse proxy.
    #[structopt(long)]
    plaintext: bool,

    /// Path to TLS certificate.
    #[structopt(long = "tls-cert", default_value = "tls_certificate.pem")]
    tls_cert_file: String,

    /// Path to TLS private key.
    #[structopt(long = "tls-priv_key", default_value = "tls_private_key.pem")]
    tls_priv_key_file: String,

    /// Set port to bind to.
    #[structopt(short = "P", long = "port", default_value = "443")]
    port: u16,

    /// Set IP to bind to.
    #[structopt(short = "H", long = "host", default_value = "0.0.0.0")]
    host: Ipv4Addr,
}

// TODO: Rate limiting
// TODO: OGS mode & FS mode
// TODO: Distribute as binary

#[tokio::main]
async fn main() {
    // Parse arguments
    let opt = Opt::from_args();
    let addr = SocketAddr::new(IpAddr::V4(opt.host), opt.port);
    // Print the server public key
    let public_key = hex::encode(crypto::PUBLIC_KEY.as_bytes());
    println!("The public key of this server is: {}", public_key);
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
    if opt.plaintext {
        println!("Running in plaintext mode on {}.", addr);
        let serve_routes_future = warp::serve(routes).run(addr);
        // Keep futures alive
        join!(
            prune_pending_tokens_future,
            prune_tokens_future,
            prune_files_future,
            serve_routes_future
        );
    } else {
        println!("Running on {} with TLS.", addr);
        let serve_routes_future = warp::serve(routes)
            .tls()
            .cert_path(opt.tls_cert_file)
            .key_path(opt.tls_priv_key_file)
            .run(addr);
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
