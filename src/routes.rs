use warp::{Filter, Rejection};

use super::handlers;
use super::models;
use super::storage;

/// POST /messages
pub fn send_message(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("messages"))
        .and(warp::body::content_length_limit(10 * 1024 * 1024)) // Match storage server
        .and(warp::body::json()) // Expect JSON
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::insert_message)
        .recover(handle_error);
}

/// GET /messages
/// 
/// Returns either the last `limit` messages or all messages since `from_server_id, limited to `limit`.
pub fn get_messages(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path("messages"))
        .and(warp::query::<models::QueryOptions>())
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::get_messages)
        .recover(handle_error);
}

/// DELETE /messages/:id
pub fn delete_message(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::delete()
        .and(warp::path!("messages" / i64))
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::delete_message)
        .recover(handle_error);
}

/// GET /deleted_messages
pub fn get_deleted_messages(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path("deleted_messages"))
        .and(warp::query::<models::QueryOptions>())
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::get_deleted_messages)
        .recover(handle_error);
}

/// GET /moderators
pub fn get_moderators(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path("moderators"))
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::get_moderators)
        .recover(handle_error);
}

// Utilities

pub fn get_all(
    db_pool: &storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return send_message(db_pool.clone())
        .or(get_messages(db_pool.clone()))
        .or(delete_message(db_pool.clone()))
        .or(get_deleted_messages(db_pool.clone()))
        .or(get_moderators(db_pool.clone()));
}

async fn handle_error(e: Rejection) -> Result<impl warp::Reply, Rejection> {
    let reply = warp::reply::reply();
    if let Some(models::ValidationError) = e.find() {
        return Ok(warp::reply::with_status(reply, warp::http::StatusCode::BAD_REQUEST)); // 400
    }
    if let Some(storage::DatabaseError) = e.find() {
        return Ok(warp::reply::with_status(reply, warp::http::StatusCode::INTERNAL_SERVER_ERROR)); // 500
    }
    return Err(e);
}