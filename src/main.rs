use warp::Filter;

mod handlers;
mod models;
mod routes;
mod storage;

#[tokio::main]
async fn main() {
    // Database
    let db_pool = storage::get_db_pool();
    let db_conn = storage::get_db_conn(&db_pool).unwrap(); // Force
    storage::create_table_if_needed(&db_conn);
    // Routes
    let send_message = routes::send_message(db_pool.clone());
    let get_messages = routes::get_messages(db_pool.clone());
    let delete_message = routes::delete_message(db_pool.clone());
    let routes = send_message.or(get_messages).or(delete_message);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
