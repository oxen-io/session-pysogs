use std::{fs, path::PathBuf};

use futures::join;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio;
use warp::Filter;

use structopt::StructOpt;

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
    /// Run in plaintext mode for use behind a reverse proxy
    #[structopt(long)]
    plaintext: bool,

    /// Path to tls certificate
    #[structopt(long = "tls-cert")]
    tls_cert_file: PathBuf,

    /// Path to tls private key
    #[structopt(long = "tls-key")]
    tls_priv_key_file: PathBuf,

    /// Set port to bind to
    #[structopt(short, long, default_value = "443")]
    port: u16,

    /// Set ip to bind to
    #[structopt(short = "H", long = "host", default_value = "0.0.0.0")]
    host: Ipv4Addr,
}

#[tokio::main]
async fn main() {

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
    // Create the main room
    let main_room = "main";
    storage::create_database_if_needed(main_room);
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
        join!(prune_pending_tokens_future, prune_tokens_future, prune_files_future, serve_routes_future);
    } else {
        println!("Running on {} with TLS.", addr);
        let serve_routes_future = warp::serve(routes)
            .tls()
            .cert_path(opt.tls_cert_file)
            .key_path(opt.tls_priv_key_file)
            .run(addr);
        // Keep futures alive
        join!(prune_pending_tokens_future, prune_tokens_future, prune_files_future, serve_routes_future);
    }
}
