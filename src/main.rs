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
    let db_manager = r2d2_sqlite::SqliteConnectionManager::file("database.db");
    let pool = r2d2::Pool::new(db_manager).unwrap();
    let conn = pool.get().unwrap();
    storage::create_tables_if_needed(&conn);
    let f_0 = storage::prune_pending_tokens_periodically(pool.clone());
    let routes = routes::root().or(routes::lsrpc(pool.clone()));
    let f_1 = warp::serve(routes)
        .tls()
        .cert_path("tls_certificate.pem")
        .key_path("tls_private_key.pem")
        .run(([0, 0, 0, 0], 443));
    join!(f_0, f_1);
}
