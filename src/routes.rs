use warp::{Filter, http::StatusCode, Rejection};

use super::crypto;
use super::handlers;
use super::lsrpc;
use super::models;
use super::rpc;
use super::storage;

/// POST /loki/v3/lsrpc
pub fn lsrpc(
    db_pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("loki")).and(warp::path("v3")).and(warp::path("lsrpc"))
        .and(warp::body::content_length_limit(10 * 1024 * 1024)) // Match storage server
        .and(warp::body::bytes()) // Expect bytes
        .and(warp::any().map(move || db_pool.clone()))
        .and_then(lsrpc::handle_lsrpc_request)
        .recover(handle_error);
}

async fn handle_error(e: Rejection) -> Result<impl warp::Reply, Rejection> {
    let reply = warp::reply::reply();
    if let Some(models::ValidationError) = e.find() {
        return Ok(warp::reply::with_status(reply, StatusCode::BAD_REQUEST)); // 400
    }
    if let Some(crypto::DecryptionError) = e.find() {
        return Ok(warp::reply::with_status(reply, StatusCode::BAD_REQUEST)); // 400
    }
    if let Some(lsrpc::ParsingError) = e.find() {
        return Ok(warp::reply::with_status(reply, StatusCode::BAD_REQUEST)); // 400
    }
    if let Some(rpc::InvalidRequestError) = e.find() {
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