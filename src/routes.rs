use warp::{reply::Reply, reply::Response, Filter, Rejection};

use super::errors;
use super::handlers;
use super::onion_requests;

/// GET /
pub fn root() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get().and(warp::path::end()).and_then(root_html);
}

/// POST /loki/v3/lsrpc
pub fn lsrpc() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("loki"))
        .and(warp::path("v3"))
        .and(warp::path("lsrpc"))
        .and(warp::body::content_length_limit(10 * 1024 * 1024)) // Match storage server
        .and(warp::body::bytes()) // Expect bytes
        .and_then(onion_requests::handle_onion_request)
        // It's possible for an error to occur before we have the symmetric key needed
        // to encrypt the response. In this scenario we still want to return a useful
        // status code to the receiving Service Node.
        .recover(into_response);
}

/// POST /rooms
///
/// Not publicly exposed.
pub fn create_room() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("rooms"))
        .and(warp::body::json())
        .and_then(handlers::create_room);
}

/// DELETE /rooms/:id
///
/// Not publicly exposed.
pub fn delete_room() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::delete().and(warp::path!("rooms" / String)).and_then(handlers::delete_room);
}

/// POST /moderators
///
/// Not publicly exposed.
pub fn add_moderator() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("moderators"))
        .and(warp::body::json())
        .and_then(handlers::add_moderator);
}

/// POST /delete_moderator
///
/// Not publicly exposed.
pub fn delete_moderator() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::post()
        .and(warp::path("delete_moderator"))
        .and(warp::body::json())
        .and_then(handlers::delete_moderator);
}

/// GET /url
///
/// Not publicly exposed.
pub fn get_url() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get().and(warp::path("url")).and_then(handlers::get_url);
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
