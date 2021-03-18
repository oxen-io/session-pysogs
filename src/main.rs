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
#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() {
    let public_key = hex::encode(crypto::PUBLIC_KEY.as_bytes());
    println!("The public key of this server is: {}", public_key);
    let main_room = "main";
    storage::create_database_if_needed(main_room);

    let prune_pending_tokens_future = storage::prune_pending_tokens_periodically();
    let prune_tokens_future = storage::prune_tokens_periodically();
    let routes = routes::root().or(routes::lsrpc());
    let serve_routes_future = warp::serve(routes)
        .tls()
        .cert_path("tls_certificate.pem")
        .key_path("tls_private_key.pem")
        .run(([0, 0, 0, 0], 443));
    join!(prune_pending_tokens_future, prune_tokens_future, serve_routes_future);
}
