use warp::{Filter, http::StatusCode, Rejection};

use super::errors::Error;
use super::lsrpc;
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

async fn handle_error(e: Rejection) -> Result<StatusCode, Rejection> {
    if let Some(error) = e.find::<Error>() {
        match error {
            Error::DecryptionFailed | Error::InvalidRequest | Error::ParsingFailed 
                | Error::ValidationFailed => return Ok(StatusCode::BAD_REQUEST),
            Error::Unauthorized => return Ok(StatusCode::FORBIDDEN),
            Error::DatabaseFailedInternally => return Ok(StatusCode::INTERNAL_SERVER_ERROR)
        };
    } else {
        return Err(e);
    }
}