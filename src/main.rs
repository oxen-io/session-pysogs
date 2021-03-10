mod handlers;
mod models;
mod routes;
mod storage;

#[tokio::main]
async fn main() {
    // Database
    let db_pool = storage::get_db_pool();
    let db_conn = storage::get_db_conn(&db_pool).unwrap(); // Force
    storage::create_tables_if_needed(&db_conn);
    // Routes
    let routes = routes::get_all(&db_pool);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
