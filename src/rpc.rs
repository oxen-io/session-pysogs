use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use warp::{Rejection, reply::Reply, reply::Response};

use super::errors::Error;
use super::handlers;
use super::storage;

#[derive(Deserialize, Serialize, Debug)]
pub struct RpcCall {
    pub endpoint: String,
    pub body: String,
    pub method: String,
    pub headers: HashMap<String, String>
}

pub async fn handle_rpc_call(rpc_call: RpcCall) -> Result<Response, Rejection> {
    // Get a connection pool for the given room
    let room_id = match get_room_id(&rpc_call) {
        Some(room_id) => room_id,
        None => {
            println!("Missing room ID.");
            return Err(warp::reject::custom(Error::InvalidRpcCall))
        }
    };
    let pool = storage::pool_by_room_id(&room_id);
    // Check that the endpoint is a valid URI and deconstruct it into a path
    // and query parameters.
    // Adding "http://placeholder.io" in front of the endpoint we get is a workaround
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
        "GET" => return handle_get_request(rpc_call, &path, query_params, &pool).await,
        "POST" => return handle_post_request(rpc_call, &path, auth_token, &pool).await,
        "DELETE" => return handle_delete_request(rpc_call, &path, auth_token, &pool).await,
        _ => {
            println!("Ignoring RPC call with invalid or unused HTTP method: {}.", rpc_call.method);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
    }
}

async fn handle_get_request(rpc_call: RpcCall, path: &str, query_params: HashMap<String, String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Switch on the path    
    if path.starts_with("files") {
        let components: Vec<&str> = path.split("/").collect(); // Split on subsequent slashes
        if components.len() != 2 {
            println!("Invalid endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
        let file_id = components[1];
        return handlers::get_file(file_id).await.map(|json| warp::reply::json(&json).into_response());
    }
    match path {
        "messages" => return handlers::get_messages(query_params, pool).await,
        "deleted_messages" => return handlers::get_deleted_messages(query_params, pool).await,
        "moderators" => return handlers::get_moderators(pool).await,
        "block_list" => return handlers::get_banned_public_keys(pool).await,
        "member_count" => return handlers::get_member_count(pool).await,
        "auth_token_challenge" => {
            return handlers::get_auth_token_challenge(query_params, pool).await.map(|json| warp::reply::json(&json).into_response());
        },
        _ => {
            println!("Ignoring RPC call with invalid or unused endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));        
        }
    }
}

async fn handle_post_request(rpc_call: RpcCall, path: &str, auth_token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    match path {
        "messages" => {
            let message = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse message from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::insert_message(message, auth_token, pool).await; 
        },
        "block_list" => {
            #[derive(Debug, Deserialize)]
            struct JSON { public_key: String }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse JSON from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::ban(&json.public_key, auth_token, pool).await;
        },
        "claim_auth_token" => {
            #[derive(Debug, Deserialize)]
            struct JSON { public_key: String }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse JSON from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::claim_auth_token(&json.public_key, auth_token, pool).await;
        },
        "files" => {
            #[derive(Debug, Deserialize)]
            struct JSON { file: String }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    println!("Couldn't parse JSON from: {} due to error: {}.", rpc_call.body, e);
                    return Err(warp::reject::custom(Error::InvalidRpcCall));
                }
            };
            return handlers::store_file(&json.file, pool).await;
        },
        _ => {
            println!("Ignoring RPC call with invalid or unused endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));        
        }
    }
}

async fn handle_delete_request(rpc_call: RpcCall, path: &str, auth_token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // DELETE /messages/:server_id
    if path.starts_with("messages") {
        let components: Vec<&str> = path.split("/").collect(); // Split on subsequent slashes
        if components.len() != 2 {
            println!("Invalid endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
        let server_id: i64 = match components[1].parse() {
            Ok(server_id) => server_id,
            Err(_) => {
                println!("Invalid endpoint: {}.", rpc_call.endpoint);
                return Err(warp::reject::custom(Error::InvalidRpcCall));
            }
        };
        return handlers::delete_message(server_id, auth_token, pool).await;
    }
    // DELETE /block_list/:public_key
    if path.starts_with("block_list") {
        let components: Vec<&str> = path.split("/").collect(); // Split on subsequent slashes
        if components.len() != 2 {
            println!("Invalid endpoint: {}.", rpc_call.endpoint);
            return Err(warp::reject::custom(Error::InvalidRpcCall));
        }
        let public_key = components[1].to_string();
        return handlers::unban(&public_key, auth_token, pool).await;
    }
    // DELETE /auth_token
    if path == "auth_token" {
        return handlers::delete_auth_token(auth_token, pool).await;
    }
    // Unrecognized endpoint
    println!("Ignoring RPC call with invalid or unused endpoint: {}.", rpc_call.endpoint);
    return Err(warp::reject::custom(Error::InvalidRpcCall));
}

// Utilities

fn get_auth_token(rpc_call: &RpcCall) -> Option<String> {
    if rpc_call.headers.is_empty() { return None; }
    return rpc_call.headers.get("Authorization").map(|s| s.to_string());
}

fn get_room_id(rpc_call: &RpcCall) -> Option<String> {
    if rpc_call.headers.is_empty() { return None; }
    return rpc_call.headers.get("Room").map(|s| s.to_string());
}