use std::collections::HashMap;
use std::convert::TryInto;
use std::path::Path;

use log::{error, info, warn};
use parking_lot::RwLock;
use rand::{thread_rng, Rng};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

use super::crypto;
use super::errors::Error;
use super::models;
use super::rpc;
use super::storage;

enum AuthorizationLevel {
    Basic,
    Moderator,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenericStringResponse {
    pub status_code: u16,
    pub result: String,
}

pub const SESSION_VERSION_UPDATE_INTERVAL: i64 = 30 * 60;

lazy_static::lazy_static! {

    pub static ref SESSION_VERSIONS: RwLock<HashMap<String, (i64, String)>> = RwLock::new(HashMap::new());
}

// Rooms

// Not publicly exposed.
pub async fn create_room(room: models::Room) -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the room
    let stmt = "REPLACE INTO main (id, name) VALUES (?1, ?2)";
    match conn.execute(&stmt, params![&room.id, &room.name]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't create room due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Set up the database
    storage::create_database_if_needed(&room.id);
    // Return
    info!("Added room with ID: {}", &room.id);
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

// Not publicly exposed.
pub async fn delete_room(id: String) -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the room
    let stmt = "DELETE FROM main WHERE id = (?1)";
    match conn.execute(&stmt, params![&id]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't delete room due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Don't auto-delete the database file (the server operator might want to keep it around)
    // Return
    info!("Deleted room with ID: {}", &id);
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

pub fn get_room(room_id: &str) -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Get the room info if possible
    let raw_query = "SELECT id, name FROM main where id = (?1)";
    let room = match conn.query_row(&raw_query, params![room_id], |row| {
        Ok(models::Room { id: row.get(0)?, name: row.get(1)? })
    }) {
        Ok(info) => info,
        Err(_) => return Err(warp::reject::custom(Error::NoSuchRoom)),
    };
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        room: models::Room,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), room };
    return Ok(warp::reply::json(&response).into_response());
}

pub fn get_all_rooms() -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Get the room info if possible
    let raw_query = "SELECT id, name FROM main";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query
        .query_map(params![], |row| Ok(models::Room { id: row.get(0)?, name: row.get(1)? }))
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get rooms due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let rooms: Vec<models::Room> = rows.filter_map(|result| result.ok()).collect();
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        rooms: Vec<models::Room>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), rooms };
    return Ok(warp::reply::json(&response).into_response());
}

// Files

pub async fn store_file(
    room_id: Option<String>, base64_encoded_bytes: &str, auth_token: Option<String>,
    pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // It'd be nice to use the UUID crate for the file ID, but clients want an integer ID
    const UPPER_BOUND: u64 = 1u64 << 53; // JS has trouble if we go higher than this
    let id: u64 = thread_rng().gen_range(0..UPPER_BOUND);
    let now = chrono::Utc::now().timestamp();
    // Check authorization level if needed
    match rpc::MODE {
        rpc::Mode::OpenGroupServer => {
            let auth_token = auth_token.ok_or_else(|| warp::reject::custom(Error::NoAuthToken))?;
            let (has_authorization_level, _) =
                has_authorization_level(&auth_token, AuthorizationLevel::Basic, pool)?;
            if !has_authorization_level {
                return Err(warp::reject::custom(Error::Unauthorized));
            }
        }
        rpc::Mode::FileServer => { /* Do nothing */ }
    }
    // Parse bytes
    let bytes = match base64::decode(base64_encoded_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Couldn't parse bytes from invalid base64 encoding due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Update the database
    // We do this * before * storing the actual file, so that in case something goes
    // wrong we're not left with files that'll never be pruned.
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // INSERT rather than REPLACE so that on the off chance there's already a file with this exact
    // id (i.e. timestamp) we simply error out and get the client to retry.
    let stmt = "INSERT INTO files (id, timestamp) VALUES (?1, ?2)";
    let _ = match conn.execute(&stmt, params![id.to_string(), now]) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't insert file record due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Write to file
    // room_id is guaranteed to be present at this point because we checked the auth
    // token (the auth token will have been rejected if room_id is missing).
    let room_id = room_id.unwrap();
    let _ = std::fs::create_dir_all(format!("files/{}_files", &room_id));
    let raw_path = format!("files/{}_files/{}", &room_id, &id);
    let path = Path::new(&raw_path);
    let mut file = match File::create(path).await {
        Ok(file) => file,
        Err(e) => {
            error!("Couldn't store file due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    match file.write_all(&bytes).await {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't store file due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        result: u64,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), result: id };
    return Ok(warp::reply::json(&response).into_response());
}

pub async fn get_file(
    room_id: Option<String>, id: u64, auth_token: Option<String>,
    pool: &storage::DatabaseConnectionPool,
) -> Result<GenericStringResponse, Rejection> {
    // Doesn't return a response directly for testing purposes
    // Check authorization level if needed
    match rpc::MODE {
        rpc::Mode::OpenGroupServer => {
            let auth_token = auth_token.ok_or_else(|| warp::reject::custom(Error::NoAuthToken))?;
            let (has_authorization_level, _) =
                has_authorization_level(&auth_token, AuthorizationLevel::Basic, pool)?;
            if !has_authorization_level {
                return Err(warp::reject::custom(Error::Unauthorized));
            }
        }
        rpc::Mode::FileServer => { /* Do nothing */ }
    }
    // Try to read the file
    let mut bytes = vec![];
    // room_id is guaranteed to be present at this point because we checked the auth
    // token (the auth token will have been rejected if room_id is missing).
    let raw_path = format!("files/{}_files/{}", room_id.unwrap(), id);
    let path = Path::new(&raw_path);
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(e) => {
            error!("Couldn't read file due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    match file.read_to_end(&mut bytes).await {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't read file due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Base64 encode the result
    let base64_encoded_bytes = base64::encode(bytes);
    // Return
    let json = GenericStringResponse {
        status_code: StatusCode::OK.as_u16(),
        result: base64_encoded_bytes,
    };
    return Ok(json);
}

pub async fn get_group_image(room_id: &str) -> Result<Response, Rejection> {
    // Try to read the file
    let mut bytes = vec![];
    let raw_path = format!("files/{}", room_id);
    let path = Path::new(&raw_path);
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(e) => {
            error!("Couldn't read file due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    match file.read_to_end(&mut bytes).await {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't read file due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Base64 encode the result
    let base64_encoded_bytes = base64::encode(bytes);
    // Return
    let json = GenericStringResponse {
        status_code: StatusCode::OK.as_u16(),
        result: base64_encoded_bytes,
    };
    return Ok(warp::reply::json(&json).into_response());
}

pub async fn set_group_image(
    base64_encoded_bytes: &str, room_id: &str, auth_token: &str,
    pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Parse bytes
    let bytes = match base64::decode(base64_encoded_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Couldn't parse bytes from invalid base64 encoding due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Write to file
    let raw_path = format!("files/{}", room_id);
    let path = Path::new(&raw_path);
    let mut file = match File::create(path).await {
        Ok(file) => file,
        Err(e) => {
            error!("Couldn't set group image due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    match file.write_all(&bytes).await {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't set group image due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        room_id: String,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), room_id: room_id.to_string() };
    return Ok(warp::reply::json(&response).into_response());
}

// Authentication

pub fn get_auth_token_challenge(
    query_params: HashMap<String, String>, pool: &storage::DatabaseConnectionPool,
) -> Result<models::Challenge, Rejection> {
    // Doesn't return a response directly for testing purposes
    // Get the public key
    let hex_public_key = query_params
        .get("public_key")
        .ok_or_else(|| warp::reject::custom(Error::InvalidRpcCall))?;
    // Validate the public key
    if !is_valid_public_key(hex_public_key) {
        warn!("Ignoring challenge request for invalid public key: {}.", hex_public_key);
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Convert the public key to bytes and cut off the version byte
    // This is safe because we know it has a length of 32 at this point
    let public_key: [u8; 32] = hex::decode(hex_public_key).unwrap()[1..].try_into().unwrap();
    // Generate an ephemeral key pair
    let (ephemeral_private_key, ephemeral_public_key) = crypto::generate_x25519_key_pair();
    // Generate a symmetric key from the requesting user's public key and the ephemeral private key
    let symmetric_key = crypto::get_x25519_symmetric_key(&public_key, &ephemeral_private_key)?;
    // Generate a random token (or get the currently pending one if possible)
    let pending_tokens = get_pending_tokens(&hex_public_key, &pool)?;
    let token: Vec<u8>;
    if !pending_tokens.is_empty() {
        token = pending_tokens[0].1.clone();
    } else {
        let mut buffer = [0u8; 48];
        thread_rng().fill(&mut buffer[..]);
        token = buffer.to_vec();
    }
    // Store the (pending) token
    // Note that a given public key can have multiple pending tokens
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let now = chrono::Utc::now().timestamp();
    let stmt = "INSERT INTO pending_tokens (public_key, timestamp, token) VALUES (?1, ?2, ?3)";
    let _ = match conn.execute(&stmt, params![hex_public_key, now, token]) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't insert pending token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Encrypt the token with the symmetric key
    let ciphertext = crypto::encrypt_aes_gcm(&token, &symmetric_key)?;
    // Return
    return Ok(models::Challenge {
        ciphertext: base64::encode(ciphertext),
        ephemeral_public_key: base64::encode(ephemeral_public_key.to_bytes()),
    });
}

pub fn claim_auth_token(
    public_key: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) {
        warn!("Ignoring claim token request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Validate the token
    if hex::decode(auth_token).is_err() {
        warn!("Ignoring claim token request for invalid token.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Get the pending tokens for the given public key
    let pending_tokens = get_pending_tokens(&public_key, &pool)?;
    // Check that the token being claimed is in fact one of the pending tokens
    let claim = hex::decode(auth_token).unwrap(); // Safe because we validated it above
    let index = pending_tokens
        .iter()
        .position(|(_, pending_token)| *pending_token == claim)
        .ok_or(Error::Unauthorized)?;
    let token = &pending_tokens[index].1;
    // Store the claimed token
    let stmt = "INSERT INTO tokens (public_key, timestamp, token) VALUES (?1, ?2, ?3)";
    let now = chrono::Utc::now().timestamp();
    match conn.execute(&stmt, params![public_key, now, hex::encode(token)]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't insert token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Delete all pending tokens for the given public key
    let stmt = "DELETE FROM pending_tokens WHERE public_key = (?1)";
    match conn.execute(&stmt, params![public_key]) {
        Ok(_) => (),
        Err(e) => error!("Couldn't delete pending tokens due to error: {}.", e), // It's not catastrophic if this fails
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

pub fn delete_auth_token(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, requesting_public_key) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Delete the token
    let stmt = "DELETE FROM tokens WHERE public_key = (?1)";
    match conn.execute(&stmt, params![requesting_public_key]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't delete token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

// Message sending & receiving

/// Inserts the given `message` into the database if it's valid.
pub fn insert_message(
    mut message: models::Message, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the message
    if !message.is_valid() {
        warn!("Ignoring invalid message.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Check authorization level
    let (has_authorization_level, requesting_public_key) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Check if the requesting user needs to be rate limited
    let last_5_messages = get_last_5_messages(&requesting_public_key, pool)?;
    let should_rate_limit: bool;
    if last_5_messages.len() == 5 {
        let interval = timestamp - last_5_messages[4].timestamp;
        // Rate limit if the interval between the fifth last message and the current timestamp is
        // less than 16 seconds; in other words, the user can send 5 messages every 16 seconds. This
        // is a very crude way of rate limiting, but it should be sufficient for now.
        should_rate_limit = interval < 16 * 1000;
    } else {
        should_rate_limit = false;
    }
    if should_rate_limit {
        return Err(warp::reject::custom(Error::RateLimited));
    }
    // Insert the message
    message.timestamp = timestamp;
    let stmt =
        "INSERT INTO messages (public_key, timestamp, data, signature, is_deleted) VALUES (?1, ?2, ?3, ?4, ?5)";
    match tx.execute(
        &stmt,
        params![&requesting_public_key, message.timestamp, message.data, message.signature, 0],
    ) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't insert message due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    let id = tx.last_insert_rowid();
    message.server_id = Some(id);
    message.public_key = Some(requesting_public_key);
    // Commit
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        message: models::Message,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), message };
    return Ok(warp::reply::json(&response).into_response());
}

fn get_last_5_messages(
    public_key: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<models::Message>, Rejection> {
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let raw_query =
        "SELECT id, public_key, timestamp, data, signature FROM messages WHERE public_key = (?1) ORDER BY timestamp DESC LIMIT 5";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![public_key], |row| {
        Ok(models::Message {
            server_id: row.get(0)?,
            public_key: row.get(1)?,
            timestamp: row.get(2)?,
            data: row.get(3)?,
            signature: row.get(4)?,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get last 5 messages due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    return Ok(rows.filter_map(|result| result.ok()).collect());
}

/// Returns either the last `limit` messages or all messages since `from_server_id, limited to `limit`.
pub fn get_messages(
    query_params: HashMap<String, String>, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<models::Message>, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Unwrap query parameters
    let from_server_id: i64;
    if let Some(str) = query_params.get("from_server_id") {
        from_server_id = str.parse().unwrap_or(0);
    } else {
        from_server_id = 0;
    }
    let limit: u16; // Never return more than 256 messages at once
    if let Some(str) = query_params.get("limit") {
        limit = std::cmp::min(str.parse().unwrap_or(256), 256);
    } else {
        limit = 256;
    }
    // Query the database
    let raw_query: &str;
    if query_params.get("from_server_id").is_some() {
        raw_query = "SELECT id, public_key, timestamp, data, signature FROM messages WHERE id > (?1) AND is_deleted = 0 ORDER BY id ASC LIMIT (?2)";
    } else {
        raw_query = "SELECT id, public_key, timestamp, data, signature FROM messages WHERE is_deleted = 0 ORDER BY id DESC LIMIT (?2)";
    }
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![from_server_id, limit], |row| {
        Ok(models::Message {
            server_id: row.get(0)?,
            public_key: row.get(1)?,
            timestamp: row.get(2)?,
            data: row.get(3)?,
            signature: row.get(4)?,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get messages due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let messages: Vec<models::Message> = rows.filter_map(|result| result.ok()).collect();
    // Record activity for usage statistics
    // We want to fail silently if any of this goes wrong
    match update_usage_statistics(auth_token, pool) {
        Ok(_) => (),
        Err(_) => println!("Couldn't update usage stats."),
    };
    // Return the messages
    return Ok(messages);
}

fn update_usage_statistics(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<(), Rejection> {
    let public_key = get_public_key_for_auth_token(auth_token, pool)?;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let now = chrono::Utc::now().timestamp();
    let stmt = "INSERT OR REPLACE INTO user_activity (public_key, last_active) VALUES(?1, ?2)";
    conn.execute(&stmt, params![public_key, now]).map_err(|_| Error::DatabaseFailedInternally)?;
    return Ok(());
}

// Message deletion

/// Deletes the messages with the given `ids` from the database, if present.
pub fn delete_messages(
    ids: Vec<i64>, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // FIXME: Right now a situation can occur where a non-moderator user selects multiple
    // messages, some of which are their own and some of which aren't, and then hits this endpoint.
    // When they do, some of the messages would be deleted but an error status code would be
    // returned, prompting the client to roll back the deletions they made locally. The only thing
    // preventing this scenario from occurring right now is that we don't allow users to make such
    // a selection in the Session UI. In the future we should take a better approach to make it
    // impossible.
    for id in ids {
        delete_message(id, auth_token, pool)?;
    }
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Deletes the message with the given `id` from the database, if it's present.
pub fn delete_message(
    id: i64, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, requesting_public_key) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Check that the requesting user is either the sender of the message or a moderator
    let sender_option: Option<String> = {
        let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
        let raw_query = "SELECT public_key FROM messages WHERE id = (?1)";
        let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
        let rows = match query.query_map(params![id], |row| row.get(0)) {
            Ok(rows) => rows,
            Err(e) => {
                error!("Couldn't delete message due to error: {}.", e);
                return Err(warp::reject::custom(Error::DatabaseFailedInternally));
            }
        };
        let public_key = rows.filter_map(|result| result.ok()).next();
        public_key
    };
    let sender =
        sender_option.ok_or_else(|| warp::reject::custom(Error::DatabaseFailedInternally))?;
    if !is_moderator(&requesting_public_key, pool)? && requesting_public_key != sender {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Delete the message if it's present
    let stmt = "UPDATE messages SET public_key = 'deleted', timestamp = 0, data = 'deleted', signature = 'deleted', is_deleted = 1 WHERE id = (?1)";
    let count = match tx.execute(&stmt, params![id]) {
        Ok(count) => count,
        Err(e) => {
            error!("Couldn't delete message due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Update the deletions table if needed
    if count > 0 {
        let stmt = "INSERT INTO deleted_messages (deleted_message_id) VALUES (?1)";
        match tx.execute(&stmt, params![id]) {
            Ok(_) => (),
            Err(e) => {
                error!("Couldn't delete message due to error: {}.", e);
                return Err(warp::reject::custom(Error::DatabaseFailedInternally));
            }
        };
    }
    // Commit
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Returns either the last `limit` deleted messages or all deleted messages since `from_server_id, limited to `limit`.
pub fn get_deleted_messages(
    query_params: HashMap<String, String>, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<models::DeletedMessage>, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Unwrap query parameters
    let from_server_id: i64;
    if let Some(str) = query_params.get("from_server_id") {
        from_server_id = str.parse().unwrap_or(0);
    } else {
        from_server_id = 0;
    }
    let limit: u16; // Never return more than 256 messages at once
    if let Some(str) = query_params.get("limit") {
        limit = std::cmp::min(str.parse().unwrap_or(256), 256);
    } else {
        limit = 256;
    }
    // Query the database
    let raw_query: &str;
    if query_params.get("from_server_id").is_some() {
        raw_query = "SELECT id, deleted_message_id FROM deleted_messages WHERE id > (?1) ORDER BY id ASC LIMIT (?2)";
    } else {
        raw_query =
            "SELECT id, deleted_message_id FROM deleted_messages ORDER BY id DESC LIMIT (?2)";
    }
    let mut query = conn.prepare(raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![from_server_id, limit], |row| {
        Ok(models::DeletedMessage { id: row.get(0)?, deleted_message_id: row.get(1)? })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get deleted messages due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let deleted_messages: Vec<models::DeletedMessage> =
        rows.filter_map(|result| result.ok()).collect();
    // Return the IDs
    return Ok(deleted_messages);
}

// Moderation

pub async fn add_moderator_public(
    body: models::ChangeModeratorRequestBody, auth_token: &str,
) -> Result<Response, Rejection> {
    let pool = storage::pool_by_room_id(&body.room_id);
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, &pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    return add_moderator(body).await;
}

// Not publicly exposed.
pub async fn add_moderator(
    body: models::ChangeModeratorRequestBody,
) -> Result<Response, Rejection> {
    // Get a database connection
    let pool = storage::pool_by_room_id(&body.room_id);
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the moderator
    let stmt = "INSERT INTO moderators (public_key) VALUES (?1)";
    match conn.execute(&stmt, params![&body.public_key]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't make public key moderator due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Return
    info!("Added moderator: {} to room with ID: {}", &body.public_key, &body.room_id);
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

pub async fn delete_moderator_public(
    body: models::ChangeModeratorRequestBody, auth_token: &str,
) -> Result<Response, Rejection> {
    let pool = storage::pool_by_room_id(&body.room_id);
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, &pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    return delete_moderator(body).await;
}

// Not publicly exposed.
pub async fn delete_moderator(
    body: models::ChangeModeratorRequestBody,
) -> Result<Response, Rejection> {
    // Get a database connection
    let pool = storage::pool_by_room_id(&body.room_id);
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the moderator
    let stmt = "DELETE FROM moderators WHERE public_key = (?1)";
    match conn.execute(&stmt, params![&body.public_key]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't delete moderator due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Return
    info!("Deleted moderator: {} from room with ID: {}", &body.public_key, &body.room_id);
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Returns the full list of moderators.
pub fn get_moderators(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<String>, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Return
    let public_keys = get_moderators_vector(pool)?;
    return Ok(public_keys);
}

/// Bans the given `public_key` if the requesting user is a moderator, and deletes
/// all messages sent by `public_key`.
pub fn ban_and_delete_all_messages(
    public_key: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) {
        warn!("Ignoring ban and delete all messages request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Ban the user
    ban(public_key, auth_token, pool)?;
    // Get the IDs of the messages to delete
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let raw_query = "SELECT id FROM messages WHERE public_key = (?1) AND is_deleted = 0";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![public_key], |row| Ok(row.get(0)?)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't delete messages due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let ids: Vec<i64> = rows.filter_map(|result| result.ok()).collect();
    // Delete all messages sent by the given public key
    delete_messages(ids, auth_token, pool)?;
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Bans the given `public_key` if the requesting user is a moderator.
pub fn ban(
    public_key: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) {
        warn!("Ignoring ban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Don't double ban public keys
    if is_banned(&public_key, pool)? {
        return Ok(StatusCode::OK.into_response());
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = "INSERT INTO block_list (public_key) VALUES (?1)";
    match conn.execute(&stmt, params![public_key]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't ban public key due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Unbans the given `public_key` if the requesting user is a moderator.
pub fn unban(
    public_key: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) {
        warn!("Ignoring unban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Don't double unban public keys
    if !is_banned(&public_key, pool)? {
        return Ok(StatusCode::OK.into_response());
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = "DELETE FROM block_list WHERE public_key = (?1)";
    match conn.execute(&stmt, params![public_key]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't unban public key due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Returns the full list of banned public keys.
pub fn get_banned_public_keys(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Return
    let public_keys = get_banned_public_keys_vector(pool)?;
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        banned_members: Vec<String>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), banned_members: public_keys };
    return Ok(warp::reply::json(&response).into_response());
}

// General

pub fn get_member_count(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = "SELECT COUNT(DISTINCT public_key) FROM tokens";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| row.get(0)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let public_key_count: u32 = rows
        .filter_map(|result| result.ok())
        .next()
        .ok_or_else(|| warp::reject::custom(Error::DatabaseFailedInternally))?;
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        member_count: u32,
    }
    let response =
        Response { status_code: StatusCode::OK.as_u16(), member_count: public_key_count };
    return Ok(warp::reply::json(&response).into_response());
}

pub fn compact_poll(
    request_bodies: Vec<models::CompactPollRequestBody>,
) -> Result<Response, Rejection> {
    let mut response_bodies: Vec<models::CompactPollResponseBody> = vec![];
    let main_pool = &storage::MAIN_POOL;
    let main_conn = main_pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    for request_body in request_bodies {
        // Unwrap the request body
        let models::CompactPollRequestBody {
            room_id,
            auth_token,
            from_message_server_id,
            from_deletion_server_id,
        } = request_body;
        // Check that the room hasn't been deleted
        let raw_query = "SELECT id, name FROM main where id = (?1)";
        match main_conn.query_row(&raw_query, params![room_id], |row| {
            Ok(models::Room { id: row.get(0)?, name: row.get(1)? })
        }) {
            Ok(_) => (),
            Err(_) => {
                let status_code = StatusCode::NOT_FOUND.as_u16();
                let response_body = models::CompactPollResponseBody {
                    room_id,
                    status_code,
                    messages: vec![],
                    deletions: vec![],
                    moderators: vec![],
                };
                response_bodies.push(response_body);
                continue;
            }
        };
        // Get the database connection pool
        let pool = storage::pool_by_room_id(&room_id);
        // Get the new messages
        let mut get_messages_query_params: HashMap<String, String> = HashMap::new();
        if let Some(from_message_server_id) = from_message_server_id {
            get_messages_query_params
                .insert("from_server_id".to_string(), from_message_server_id.to_string());
        }
        let messages = match get_messages(get_messages_query_params, &auth_token, &pool) {
            Ok(messages) => messages,
            Err(e) => {
                let status_code = super::errors::status_code(e);
                let response_body = models::CompactPollResponseBody {
                    room_id,
                    status_code: status_code.as_u16(),
                    messages: vec![],
                    deletions: vec![],
                    moderators: vec![],
                };
                response_bodies.push(response_body);
                continue;
            }
        };
        // Get the new deletions
        let mut get_deletions_query_params: HashMap<String, String> = HashMap::new();
        if let Some(from_deletion_server_id) = from_deletion_server_id {
            get_deletions_query_params
                .insert("from_server_id".to_string(), from_deletion_server_id.to_string());
        }
        let deletions = match get_deleted_messages(get_deletions_query_params, &auth_token, &pool) {
            Ok(deletions) => deletions,
            Err(e) => {
                let status_code = super::errors::status_code(e);
                let response_body = models::CompactPollResponseBody {
                    room_id,
                    status_code: status_code.as_u16(),
                    messages: vec![],
                    deletions: vec![],
                    moderators: vec![],
                };
                response_bodies.push(response_body);
                continue;
            }
        };
        // Get the moderators
        let moderators = match get_moderators(&auth_token, &pool) {
            Ok(moderators) => moderators,
            Err(e) => {
                let status_code = super::errors::status_code(e);
                let response_body = models::CompactPollResponseBody {
                    room_id,
                    status_code: status_code.as_u16(),
                    messages: vec![],
                    deletions: vec![],
                    moderators: vec![],
                };
                response_bodies.push(response_body);
                continue;
            }
        };
        // Add to the response
        let response_body = models::CompactPollResponseBody {
            room_id,
            status_code: StatusCode::OK.as_u16(),
            deletions,
            messages,
            moderators,
        };
        response_bodies.push(response_body);
    }
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        results: Vec<models::CompactPollResponseBody>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), results: response_bodies };
    return Ok(warp::reply::json(&response).into_response());
}

// Not publicly exposed.
pub async fn get_url() -> Result<Response, Rejection> {
    let url = super::get_url();
    return Ok(warp::reply::json(&url).into_response());
}

pub async fn get_session_version(platform: &str) -> Result<String, Rejection> {
    let mut session_versions = SESSION_VERSIONS.read().clone();
    let now = chrono::Utc::now().timestamp();
    if let Some(version_info) = session_versions.get(platform) {
        let last_updated = version_info.0;
        if now - last_updated < SESSION_VERSION_UPDATE_INTERVAL {
            let tag = version_info.1.to_string();
            println!("Returning cached value: {}", tag);
            return Ok(tag);
        }
    }
    let octocrab = octocrab::instance();
    let repo = format!("session-{}", platform);
    let handler = octocrab.repos("oxen-io", repo);
    let release = handler.releases().get_latest().await.unwrap();
    let tag = release.tag_name;
    let tuple = (now, tag.clone());
    session_versions.insert(platform.to_string(), tuple);
    *SESSION_VERSIONS.write() = session_versions.clone();
    return Ok(tag);
}

// not publicly exposed.
pub async fn get_stats_for_room(
    room: String, query_map: HashMap<String, i64>,
) -> Result<Response, Rejection> {
    let now = chrono::Utc::now().timestamp();
    let window = match query_map.get("window") {
        Some(val) => val,
        None => &3600i64,
    };

    let upperbound = match query_map.get("start") {
        Some(val) => val,
        None => &now,
    };

    let lowerbound = upperbound - window;
    let pool = storage::pool_by_room_id(&room);
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;

    let raw_query_users =
        "SELECT COUNT(public_key) FROM user_activity WHERE last_active > ?1 AND last_active <= ?2";
    let mut query_users =
        conn.prepare(&raw_query_users).map_err(|_| Error::DatabaseFailedInternally)?;

    let active = match query_users
        .query_row(params![lowerbound, upperbound], |row| Ok(row.get::<_, u32>(0)?))
    {
        Ok(row) => row,
        Err(_e) => return Err(warp::reject::custom(Error::DatabaseFailedInternally)),
    };

    let raw_query_posts =
        "SELECT COUNT(id) FROM messages WHERE timestamp >= ?1 AND timestamp <= ?2";

    let mut query_posts =
        conn.prepare(&raw_query_posts).map_err(|_| Error::DatabaseFailedInternally)?;

    let posts = match query_posts
        .query_row(params![lowerbound * 1000, upperbound * 1000], |row| Ok(row.get::<_, u32>(0)?))
    {
        Ok(row) => row,
        Err(_e) => return Err(warp::reject::custom(Error::DatabaseFailedInternally)),
    };

    // Return value
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        posts: u32,
        active_users: u32,
    }
    let response = Response { active_users: active, posts };
    return Ok(warp::reply::json(&response).into_response());
}

// Utilities

fn get_pending_tokens(
    public_key: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<(i64, Vec<u8>)>, Rejection> {
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let raw_query =
        "SELECT timestamp, token FROM pending_tokens WHERE public_key = (?1) AND timestamp > (?2)";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let now = chrono::Utc::now().timestamp();
    let expiration = now - storage::PENDING_TOKEN_EXPIRATION;
    let rows = match query
        .query_map(params![public_key, expiration], |row| Ok((row.get(0)?, row.get(1)?)))
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get pending tokens due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let pending_tokens: Vec<(i64, Vec<u8>)> = rows.filter_map(|result| result.ok()).collect();
    return Ok(pending_tokens);
}

fn get_moderators_vector(pool: &storage::DatabaseConnectionPool) -> Result<Vec<String>, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = "SELECT public_key FROM moderators";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| row.get(0)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    return Ok(rows.filter_map(|result| result.ok()).collect());
}

fn is_moderator(
    public_key: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<bool, Rejection> {
    let public_keys = get_moderators_vector(&pool)?;
    return Ok(public_keys.contains(&public_key.to_owned()));
}

fn get_banned_public_keys_vector(
    pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<String>, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = "SELECT public_key FROM block_list";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| row.get(0)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    return Ok(rows.filter_map(|result| result.ok()).collect());
}

fn is_banned(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<bool, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = "SELECT COUNT(public_key) FROM block_list WHERE public_key = (?1)";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![public_key], |row| row.get(0)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let public_key_count: u32 = rows
        .filter_map(|result| result.ok())
        .next()
        .ok_or_else(|| warp::reject::custom(Error::DatabaseFailedInternally))?;
    return Ok(public_key_count != 0);
}

fn is_valid_public_key(public_key: &str) -> bool {
    // Check that it's a valid hex encoding
    if hex::decode(public_key).is_err() {
        return false;
    }
    // Check that it's the right length
    if public_key.len() != 66 {
        return false;
    } // The version byte + 32 bytes of random data
      // It appears to be a valid public key
    return true;
}

fn get_public_key_for_auth_token(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Option<String>, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = "SELECT public_key FROM tokens WHERE token = (?1)";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![auth_token], |row| row.get(0)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let public_key: Option<String> = rows.filter_map(|result| result.ok()).next();
    // Return
    return Ok(public_key);
}

fn has_authorization_level(
    auth_token: &str, level: AuthorizationLevel, pool: &storage::DatabaseConnectionPool,
) -> Result<(bool, String), Rejection> {
    // Check that we have a public key associated with the given auth token
    let public_key_option = get_public_key_for_auth_token(auth_token, pool)?;
    let public_key = public_key_option.ok_or_else(|| warp::reject::custom(Error::NoAuthToken))?;
    // Check that the given public key isn't banned
    if is_banned(&public_key, pool)? {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // If needed, check that the given public key is a moderator
    match level {
        AuthorizationLevel::Basic => return Ok((true, public_key)),
        AuthorizationLevel::Moderator => {
            if !is_moderator(&public_key, pool)? {
                return Err(warp::reject::custom(Error::Unauthorized));
            }
            return Ok((true, public_key));
        }
    };
}
