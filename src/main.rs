use std::collections::HashMap;
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
mod options;
mod routes;
mod rpc;
mod storage;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() {
    // Parse arguments
    let opt = options::Opt::from_args();
    if opt.add_room.is_some()
        || opt.delete_room.is_some()
        || opt.add_moderator.is_some()
        || opt.delete_moderator.is_some()
    {
        // Run in command mode
        execute_commands(opt).await;
    } else {
        // Run in server mode
        let addr = SocketAddr::new(IpAddr::V4(opt.host), opt.port);
        let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3030);
        *crypto::PRIVATE_KEY_PATH.lock().unwrap() = opt.x25519_private_key;
        *crypto::PUBLIC_KEY_PATH.lock().unwrap() = opt.x25519_public_key;
        // Print the server public key
        let hex_public_key = hex::encode(crypto::PUBLIC_KEY.as_bytes());
        println!("The public key of this server is: {}", hex_public_key);
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
        let public_routes = routes::root().or(routes::lsrpc());
        let private_routes = routes::create_room()
            .or(routes::delete_room())
            .or(routes::add_moderator())
            .or(routes::delete_moderator());
        if opt.tls {
            println!("Running on {} with TLS.", addr);
            let serve_public_routes_future = warp::serve(public_routes)
                .tls()
                .cert_path(opt.tls_certificate)
                .key_path(opt.tls_private_key)
                .run(addr);
            let serve_private_routes_future = warp::serve(private_routes).run(localhost);
            // Keep futures alive
            join!(
                prune_pending_tokens_future,
                prune_tokens_future,
                prune_files_future,
                serve_public_routes_future,
                serve_private_routes_future
            );
        } else {
            println!("Running on {}.", addr);
            let serve_public_routes_future = warp::serve(public_routes).run(addr);
            let serve_private_routes_future = warp::serve(private_routes).run(localhost);
            // Keep futures alive
            join!(
                prune_pending_tokens_future,
                prune_tokens_future,
                prune_files_future,
                serve_public_routes_future,
                serve_private_routes_future
            );
        }
    }
}

async fn execute_commands(opt: options::Opt) {
    let client = reqwest::Client::new();
    let localhost = "http://127.0.0.1:3030";
    // Add a room
    if let Some(args) = opt.add_room {
        let mut params = HashMap::new();
        params.insert("id", &args[0]);
        params.insert("name", &args[1]);
        client.post(format!("{}/rooms", localhost)).json(&params).send().await.unwrap();
        println!("Added room with ID: {}", &args[0]);
    }
    // Delete a room
    if let Some(args) = opt.delete_room {
        client.delete(format!("{}/rooms/{}", localhost, args)).send().await.unwrap();
        println!("Deleted room with ID: {}", &args);
    }
    // Add a moderator
    if let Some(args) = opt.add_moderator {
        let mut params = HashMap::new();
        params.insert("public_key", &args[0]);
        params.insert("room_id", &args[1]);
        client.post(format!("{}/moderators", localhost)).json(&params).send().await.unwrap();
        println!("Added moderator: {} to room with ID: {}", &args[0], &args[1]);
    }
    // Delete a moderator
    if let Some(args) = opt.delete_moderator {
        let mut params = HashMap::new();
        params.insert("public_key", &args[0]);
        params.insert("room_id", &args[1]);
        client.post(format!("{}/delete_moderator", localhost)).json(&params).send().await.unwrap();
        println!("Deleted moderator: {} from room with ID: {}", &args[0], &args[1]);
    }
}

async fn create_default_rooms() {
    let info: Vec<(&str, &str)> = vec![("main", "Main")];
    for info in info {
        let id = info.0.to_string();
        let name = info.1.to_string();
        let room = models::Room { id, name, image_id: None };
        handlers::create_room(room).await.unwrap();
    }
}
