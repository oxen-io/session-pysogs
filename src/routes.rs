use warp::{Filter, Rejection, reply::Reply, reply::Response};

use super::errors;
use super::onion_requests;
use super::storage;

/// GET /
pub fn root() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path::end())
        .and_then(root_html);
}

/// POST /loki/v3/lsrpc
pub fn lsrpc(
    pool: storage::DatabaseConnectionPool
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("loki")).and(warp::path("v3")).and(warp::path("lsrpc"))
        .and(warp::body::content_length_limit(10 * 1024 * 1024)) // Match storage server
        .and(warp::body::bytes()) // Expect bytes
        .and(warp::any().map(move || pool.clone()))
        .and_then(onion_requests::handle_onion_request)
        // It's possible for an error to occur before we have the symmetric key needed
        // to encrypt the response. In this scenario we still want to return a useful
        // status code to the receiving Service Node.
        .recover(into_response);
}

pub async fn root_html() -> Result<Response, Rejection> {
    let body = r#"
    <html>
        <head>
            <title>Root</title>
        </head>
        <body>
            This is a Session open group server.
        </body>
    </html>
    "#;
    return Ok(warp::reply::html(body).into_response());
}

pub async fn into_response(e: Rejection) -> Result<Response, Rejection> {
    return errors::into_response(e);
}