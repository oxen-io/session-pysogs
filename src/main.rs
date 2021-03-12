mod crypto;
mod errors;
mod handlers;
mod lsrpc;
mod models;
mod routes;
mod rpc;
mod storage;

#[tokio::main]
async fn main() {
    let public_key = hex::encode(lsrpc::get_public_key().as_bytes());
    println!("The public key of this server is: {}", public_key);
    let pool = storage::pool();
    let conn = storage::conn(&pool).unwrap();
    storage::create_tables_if_needed(&conn);
    warp::serve(routes::lsrpc(pool.clone())).run(([127, 0, 0, 1], 3030)).await;
}
