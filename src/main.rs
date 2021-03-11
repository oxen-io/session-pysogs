mod crypto;
mod handlers;
mod models;
mod routes;
mod storage;

#[tokio::main]
async fn main() {
    // Database
    let pool = storage::pool();
    let conn = storage::conn(&pool).unwrap(); // Force
    storage::create_tables_if_needed(&conn);
    // Routes
    let routes = routes::get_all(&pool);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
