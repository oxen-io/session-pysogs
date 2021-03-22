use std::fs;

use argparse::{ArgumentParser, StoreTrue, Store};
use futures::join;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

#[tokio::main]
async fn main() {
    let mut plaintext = false;
    let mut tls_cert_file = "tls_certificate.pem".to_string();
    let mut tls_priv_key_file = "tls_private_key.pem".to_string();
    let mut port: u16 = 443;
    let mut ip = Ipv4Addr::new(0, 0, 0, 0);
    // Parse command line arguments
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("session open group server");
        ap.refer(&mut plaintext)
            .add_option(&["--plaintext"], StoreTrue, "run in plaintext mode for use behind a reverse proxy");
        ap.refer(&mut tls_cert_file)
            .add_option(&["--tls-cert"], Store, "path to tls certificate");
        ap.refer(&mut tls_priv_key_file)
            .add_option(&["--tls-key"], Store, "path to tls private key");
        ap.refer(&mut port)
            .add_option(&["-P", "--port"], Store, "set port to bind to");
        ap.refer(&mut ip)
            .add_option(&["-H", "--host"], Store, "set ip to bind to");
        ap.parse_args_or_exit();
    }
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
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
    if plaintext {
        println!("Running in plaintext mode on {}.", addr);
        let serve_routes_future = warp::serve(routes).run(addr);
        // Keep futures alive
        join!(prune_pending_tokens_future, prune_tokens_future, prune_files_future, serve_routes_future);
    } else {
        println!("Running on {} with TLS.", addr);
        let serve_routes_future = warp::serve(routes)
            .tls()
            .cert_path(tls_cert_file)
            .key_path(tls_priv_key_file)
            .run(addr);
        // Keep futures alive
        join!(prune_pending_tokens_future, prune_tokens_future, prune_files_future, serve_routes_future);
    }
}
