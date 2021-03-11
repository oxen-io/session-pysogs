use warp::{Filter, http::StatusCode, Rejection};

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
/// 
/// Returns either the last `limit` deleted message IDs or all deleted message IDs since `from_server_id, limited to `limit`.
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
/// 
/// Returns the full list of moderators.
pub fn get_moderators(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path("moderators"))
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::get_moderators)
        .recover(handle_error);
}

/// POST /block_list
pub fn ban(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("block_list"))
        .and(warp::body::content_length_limit(256 * 1024)) // Limit body to an arbitrary low-ish size
        .and(warp::body::json()) // Expect JSON
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::ban)
        .recover(handle_error);
}

/// DELETE /block_list/:public_key
pub fn unban(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::delete()
        .and(warp::path!("block_list" / String))
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::unban)
        .recover(handle_error);
}

/// GET /block_list
/// 
/// Returns the full list of banned public keys.
pub fn get_block_list(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path("block_list"))
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::get_banned_public_keys)
        .recover(handle_error);
}

/// GET /member_count
pub fn get_member_count(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path("member_count"))
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(handlers::get_member_count)
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
        .or(get_moderators(db_pool.clone()))
        .or(ban(db_pool.clone()))
        .or(unban(db_pool.clone()))
        .or(get_block_list(db_pool.clone()))
        .or(get_member_count(db_pool.clone()));
}

async fn handle_error(e: Rejection) -> Result<impl warp::Reply, Rejection> {
    let reply = warp::reply::reply();
    if let Some(models::ValidationError) = e.find() {
        return Ok(warp::reply::with_status(reply, StatusCode::BAD_REQUEST)); // 400
    }
    if let Some(handlers::UnauthorizedError) = e.find() {
        return Ok(warp::reply::with_status(reply, StatusCode::FORBIDDEN)); // 403
    }
    if let Some(storage::DatabaseError) = e.find() {
        return Ok(warp::reply::with_status(reply, StatusCode::INTERNAL_SERVER_ERROR)); // 500
    }
    return Err(e);
}