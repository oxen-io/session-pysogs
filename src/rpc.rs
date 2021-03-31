use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

use super::errors::Error;
use super::handlers;
use super::models;
use super::storage;

enum Mode {
    FileServer,
    OpenGroupServer,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RpcCall {
    pub endpoint: String,
    pub body: String,
    pub method: String,
    pub headers: HashMap<String, String>,
}

const MODE: Mode = Mode::OpenGroupServer;

pub async fn handle_rpc_call(rpc_call: RpcCall) -> Result<Response, Rejection> {
    // Check that the endpoint is a valid URI and deconstruct it into a path
    // and query parameters.
    // Adding "http://placeholder.io" in front of the endpoint is a workaround
    // for the fact that the URL crate doesn't accept relative URLs. There are
    // other (cleaner) ways to fix this but they tend to be much more complex.
    let raw_uri = format!("http://placeholder.io/{}", rpc_call.endpoint.trim_start_matches("/"));
    let path: String = match raw_uri.parse::<http::Uri>() {
        Ok(uri) => uri.path().trim_start_matches("/").to_string(),
        Err(e) => {
            println!("Couldn't parse URI from: {} due to error: {}.", &raw_uri, e);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
    };
    let query_params: HashMap<String, String> = match url::Url::parse(&raw_uri) {
        Ok(url) => url.query_pairs().into_owned().collect(),
        Err(e) => {
            println!("Couldn't parse URL from: {} due to error: {}.", &raw_uri, e);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
    };
    // Get the auth token if possible
    let auth_token = get_auth_token(&rpc_call);
    // Switch on the HTTP method
    match rpc_call.method.as_ref() {
        "GET" => return handle_get_request(rpc_call, &path, auth_token, query_params).await,
        "POST" => {
            let pool = get_pool_for_room(&rpc_call)?;
            return handle_post_request(rpc_call, &path, auth_token, &pool).await;
        }
        "DELETE" => {
            let pool = get_pool_for_room(&rpc_call)?;
            return handle_delete_request(&path, auth_token, &pool).await;
        }
        _ => {
            println!("Ignoring RPC call with invalid or unused HTTP method: {}.", rpc_call.method);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
    }
}

async fn handle_get_request(
    rpc_call: RpcCall, path: &str, auth_token: Option<String>,
    query_params: HashMap<String, String>,
) -> Result<Response, Rejection> {
    // Handle routes that don't require authorization first
    if path == "auth_token_challenge" {
        let pool = get_pool_for_room(&rpc_call)?;
        let challenge = handlers::get_auth_token_challenge(query_params, &pool)?;
        #[derive(Debug, Deserialize, Serialize)]
        struct Response {
            status_code: u16,
            challenge: models::Challenge,
        }
        let response = Response { status_code: StatusCode::OK.as_u16(), challenge };
        return Ok(warp::reply::json(&response).into_response());
    } else if path.starts_with("rooms") {
        reject_if_file_server_mode(path)?;
        let components: Vec<&str> = path.split("/").collect(); // Split on subsequent slashes
        if components.len() == 1 {
            return handlers::get_all_rooms();
        } else if components.len() == 2 {
            let room_id = components[1];
            return handlers::get_room(&room_id);
        } else if components.len() == 3 && components[2] == "image" {
            let room_id = components[1];
            return handlers::get_group_image(&room_id);
        } else {
            println!("Invalid endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
    }
    // Check that the auth token is present
    let auth_token = auth_token.ok_or(warp::reject::custom(Error::NoAuthToken))?;
    // Switch on the path
    let pool = get_pool_for_room(&rpc_call)?;
    if path.starts_with("files") {
        let components: Vec<&str> = path.split("/").collect(); // Split on subsequent slashes
        if components.len() != 2 {
            println!("Invalid endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
        let file_id: i64 = match components[1].parse() {
            Ok(file_id) => file_id,
            Err(_) => {
                println!("Invalid endpoint: {}.", rpc_call.endpoint);
                return Err(warp::reject::custom(Error::InvalidRpcCall));
            }
        };
        return handlers::get_file(file_id, &auth_token, &pool)
            .map(|json| warp::reply::json(&json).into_response());
    }
    match path {
        "messages" => {
            reject_if_file_server_mode(path)?;
            return handlers::get_messages(query_params, &auth_token, &pool);
        }
        "deleted_messages" => {
            reject_if_file_server_mode(path)?;
            return handlers::get_deleted_messages(query_params, &auth_token, &pool);
        }
        "moderators" => {
            reject_if_file_server_mode(path)?;
            return handlers::get_moderators(&auth_token, &pool);
        }
        "block_list" => {
            reject_if_file_server_mode(path)?;
            return handlers::get_banned_public_keys(&auth_token, &pool);
        }
        "member_count" => {
            reject_if_file_server_mode(path)?;
            return handlers::get_member_count(&auth_token, &pool);
        }
        "auth_token_challenge" => {
            let challenge = handlers::get_auth_token_challenge(query_params, &pool)?;
            #[derive(Debug, Deserialize, Serialize)]
            struct Response {
                status_code: u16,
                challenge: models::Challenge,
            }
            let response = Response { status_code: StatusCode::OK.as_u16(), challenge };
            return Ok(warp::reply::json(&response).into_response());
        }
        _ => {
            println!("Ignoring RPC call with invalid or unused endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
    }
}

async fn handle_post_request(
    rpc_call: RpcCall, path: &str, auth_token: Option<String>,
    pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check that the auth token is present
    let auth_token = auth_token.ok_or(warp::reject::custom(Error::NoAuthToken))?;
    // Switch on the path
    match path {
        "messages" => {
            reject_if_file_server_mode(path)?;
            let message = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse message from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::insert_message(message, &auth_token, pool);
        }
        "block_list" => {
            reject_if_file_server_mode(path)?;
            #[derive(Debug, Deserialize)]
            struct JSON {
                public_key: String,
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse JSON from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::ban(&json.public_key, &auth_token, pool);
        }
        "claim_auth_token" => {
            #[derive(Debug, Deserialize)]
            struct JSON {
                public_key: String,
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse JSON from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::claim_auth_token(&json.public_key, &auth_token, pool);
        }
        "files" => {
            #[derive(Debug, Deserialize)]
            struct JSON {
                file: String,
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse JSON from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::store_file(&json.file, &auth_token, pool);
        }
        _ => {
            println!("Ignoring RPC call with invalid or unused endpoint: {}.", path);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
    }
}

async fn handle_delete_request(
    path: &str, auth_token: Option<String>, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check that the auth token is present
    let auth_token = auth_token.ok_or(warp::reject::custom(Error::NoAuthToken))?;
    // DELETE /messages/:server_id
    if path.starts_with("messages") {
        reject_if_file_server_mode(path)?;
        let components: Vec<&str> = path.split("/").collect(); // Split on subsequent slashes
        if components.len() != 2 {
            println!("Invalid endpoint: {}.", path);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
        let server_id: i64 = match components[1].parse() {
            Ok(server_id) => server_id,
            Err(_) => {
                println!("Invalid endpoint: {}.", path);
                return Err(warp::reject::custom(Error::InvalidRpcCall));
            }
        };
        return handlers::delete_message(server_id, &auth_token, pool);
    }
    // DELETE /block_list/:public_key
    if path.starts_with("block_list") {
        reject_if_file_server_mode(path)?;
        let components: Vec<&str> = path.split("/").collect(); // Split on subsequent slashes
        if components.len() != 2 {
            println!("Invalid endpoint: {}.", path);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
        let public_key = components[1].to_string();
        return handlers::unban(&public_key, &auth_token, pool);
    }
    // DELETE /auth_token
    if path == "auth_token" {
        return handlers::delete_auth_token(&auth_token, pool);
    }
    // Unrecognized endpoint
    println!("Ignoring RPC call with invalid or unused endpoint: {}.", path);
    return Err(warp::reject::custom(Error::InvalidRpcCall));
}

// Utilities

fn get_pool_for_room(rpc_call: &RpcCall) -> Result<storage::DatabaseConnectionPool, Rejection> {
    let room_id: String;
    match MODE {
        // In file server mode we don't have a concept of rooms, but for convenience (i.e. so
        // we can use the same database structure) we just always use the main room
        Mode::FileServer => room_id = "main".to_string(),
        Mode::OpenGroupServer => {
            room_id = match get_room_id(&rpc_call) {
                Some(room_id) => room_id,
                None => {
                    println!("Missing room ID.");
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
        }
    }
    return Ok(storage::pool_by_room_id(&room_id));
}

fn get_auth_token(rpc_call: &RpcCall) -> Option<String> {
    if rpc_call.headers.is_empty() {
        return None;
    }
    return rpc_call.headers.get("Authorization").map(|s| s.to_string());
}

fn get_room_id(rpc_call: &RpcCall) -> Option<String> {
    if rpc_call.headers.is_empty() {
        return None;
    }
    return rpc_call.headers.get("Room").map(|s| s.to_string());
}

fn reject_if_file_server_mode(path: &str) -> Result<(), Rejection> {
    match MODE {
        Mode::FileServer => {
            println!("Ignoring RPC call with invalid or unused endpoint: {}.", path);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
        Mode::OpenGroupServer => return Ok(()),
    }
}
