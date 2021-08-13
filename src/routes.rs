use std::collections::HashMap;
use warp::{reply::Reply, reply::Response, Filter, Rejection};

use super::errors;
use super::handlers;
use super::onion_requests;

/// GET /
pub fn root() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get().and(warp::path::end()).and_then(root_html);
}

/// GET /:room_id?public_key=:public_key
pub fn fallback() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path::param())
        .and(warp::filters::query::query())
        .and_then(fallback_html);
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

/// GET /stats/:room_id?window=:seconds
///
/// Not publicly exposed
pub fn get_room_stats() -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    return warp::get()
        .and(warp::path!("stats" / String))
        .and(warp::filters::query::query())
        .and_then(handlers::get_stats_for_room);
}

pub async fn root_html() -> Result<Response, Rejection> {
    let body = r#"
    <html>
        <head>
            <title>Root</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body>
            <h1>Session Open Group Server</h1>
            <p>This is a Session open group server.</p>
        </body>
    </html>
    "#;
    return Ok(warp::reply::html(body).into_response());
}

pub async fn fallback_html(room: String, query_map: HashMap<String, String>) -> Result<Response, Rejection> {
    if !query_map.contains_key("public_key") || room == "" {
        return fallback_nopubkey_html().await
    }
    let body = r#"
    <html>
        <head>
            <title>Group</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body>
            <h1>Session Open Group Room</h1>
            <p>
                This is probably a Session open group room.<br>
                To join it, you must copy the URL and paste it in the appropriate field in your Session client.<br>
                <br>
                <b>On mobile:</b>
            </p>
            <ul>
                <li>Click the green "+" button in the main screen of the app</li>
                <li>Click on the globe icon in the left side of the "+" button</li>
                <li>Paste the open group URL and click "Enter"</li>
            </ul>
            <p><b>On desktop:</b></p>
            <ul>
                <li>Click on the "Join Open Group" button in the bottom left side of the main menu</li>
                <li>Paste the open group URL and click "Next"</li>
            </ul>
            <p><br><br>If something goes wrong, make sure that:</p>
            <ul>
                <li>This room exists</li>
                <li>You've pasted the entire link (public_key included)</li>
                <li>You're correctly connected to Session</li>
                <li>Your browser has not accidentally changed HTTP to HTTPS</li>
            </ul>
        </body>
    </html>
    "#;
    return Ok(warp::reply::html(body).into_response());
}

pub async fn fallback_nopubkey_html() -> Result<Response, Rejection> {
    let body = r#"
    <html>
        <head>
            <title>Error</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body>
            <h1>This link is wrong!</h1>
            <p>
                If you're trying to join a Session Open Group Room, this link can not work!<br>
                It's missing the public key. Make sure you're following a correct room URL.
            </p>
        </body>
    </html>
    "#;
    return Ok(warp::reply::html(body).into_response());
}

pub async fn into_response(e: Rejection) -> Result<Response, Rejection> {
    return errors::into_response(e);
}
