use std::fs;

use futures::join;
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
use argparse::{ArgumentParser, StoreTrue, Store};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(test)]
mod tests;


#[tokio::main]
async fn main() {

    // arguments default values
    let mut plaintext = false;
    let mut tls_certfile = "tls_certificate.pem".to_string();
    let mut tls_keyfile = "tls_private_key.pem".to_string();
    let mut port : u16 = 443;
    let mut bind_ip : Ipv4Addr = Ipv4Addr::new(0,0,0,0);
    // parse arguments
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("session open group server");
        ap.refer(&mut plaintext)
            .add_option(&["--plaintext"], StoreTrue,
                        "run in plaintext mode for use behind a reverse proxy");
        ap.refer(&mut tls_certfile)
            .add_option(&["--tls-cert"], Store,
                        "path to tls certificate");
        ap.refer(&mut tls_keyfile)
            .add_option(&["--tls-key"], Store,
                        "path to tls private key");
        ap.refer(&mut port)
            .add_option(&["-P", "--port"], Store,
                        "Set the port to bind on");
        ap.refer(&mut bind_ip)
            .add_option(&["-H", "--host"], Store,
                        "set ip to bind on");
        ap.parse_args_or_exit();
    }
    // create socket address
    let addr = SocketAddr::new(IpAddr::V4(bind_ip), port);
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
    let routes = warp::serve(routes::root().or(routes::lsrpc()));
    if plaintext {
        println!("!!! running in plaintext mode on {}", addr);
        let serve_routes_future = routes.run(addr);
        join!(prune_pending_tokens_future, prune_tokens_future, prune_files_future, serve_routes_future);
    } else {
        println!("running on {} with tls", addr);
        let serve_routes_future = routes.tls()
            .cert_path(tls_certfile)
            .key_path(tls_keyfile)
            .run(addr);
        join!(prune_pending_tokens_future, prune_tokens_future, prune_files_future, serve_routes_future);
    }
}
