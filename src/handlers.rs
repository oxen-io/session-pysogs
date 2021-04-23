use std::collections::HashMap;
use std::convert::TryInto;
use std::path::Path;

use chrono;
use log::{error, info, warn};
use rand::{thread_rng, Rng};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

use super::crypto;
use super::errors::Error;
use super::models;
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

// Rooms

// Not publicly exposed.
pub async fn create_room(room: models::Room) -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the room
    let stmt = format!("REPLACE INTO {} (id, name) VALUES (?1, ?2)", storage::MAIN_TABLE);
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
    let stmt = format!("DELETE FROM {} WHERE id = (?1)", storage::MAIN_TABLE);
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
    let raw_query = format!("SELECT id, name FROM {} where id = (?1)", storage::MAIN_TABLE);
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
    let raw_query = format!("SELECT id, name FROM {}", storage::MAIN_TABLE);
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
    base64_encoded_bytes: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // It'd be nice to use the UUID crate for the file ID, but clients want an integer ID
    let now = chrono::Utc::now().timestamp_nanos();
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
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
    // Update the database
    // We do this * before * storing the actual file, so that in case something goes
    // wrong we're not left with files that'll never be pruned.
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // INSERT rather than REPLACE so that on the off chance there's already a file with this exact
    // id (i.e. timestamp) we simply error out and get the client to retry.
    let stmt = format!("INSERT INTO {} (id, timestamp) VALUES (?1, ?2)", storage::FILES_TABLE);
    let _ = match conn.execute(&stmt, params![now, now]) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't insert file record due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Write to file
    let raw_path = format!("files/{}", &now);
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
        result: i64,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), result: now };
    return Ok(warp::reply::json(&response).into_response());
}

pub async fn get_file(
    id: i64, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<GenericStringResponse, Rejection> {
    // Doesn't return a response directly for testing purposes
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool)?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Try to read the file
    let mut bytes = vec![];
    let raw_path = format!("files/{}", id);
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
    let hex_public_key =
        query_params.get("public_key").ok_or(warp::reject::custom(Error::InvalidRpcCall))?;
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
    let stmt = format!(
        "INSERT INTO {} (public_key, timestamp, token) VALUES (?1, ?2, ?3)",
        storage::PENDING_TOKENS_TABLE
    );
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
        .ok_or_else(|| Error::Unauthorized)?;
    let token = &pending_tokens[index].1;
    // Store the claimed token
    let stmt = format!(
        "INSERT OR REPLACE INTO {} (public_key, token) VALUES (?1, ?2)",
        storage::TOKENS_TABLE
    );
    match conn.execute(&stmt, params![public_key, hex::encode(token)]) {
        Ok(_) => (),
        Err(e) => {
            error!("Couldn't insert token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Delete all pending tokens for the given public key
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::PENDING_TOKENS_TABLE);
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
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::TOKENS_TABLE);
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
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!(
        "INSERT INTO {} (public_key, timestamp, data, signature) VALUES (?1, ?2, ?3, ?4)",
        storage::MESSAGES_TABLE
    );
    match tx.execute(
        &stmt,
        params![&requesting_public_key, message.timestamp, message.data, message.signature],
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
    let raw_query: String;
    if query_params.get("from_server_id").is_some() {
        raw_query = format!("SELECT id, public_key, timestamp, data, signature FROM {} WHERE rowid > (?1) ORDER BY rowid ASC LIMIT (?2)", storage::MESSAGES_TABLE);
    } else {
        raw_query = format!(
            "SELECT id, public_key, timestamp, data, signature FROM {} ORDER BY rowid DESC LIMIT (?2)",
            storage::MESSAGES_TABLE
        );
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
    // Return the messages
    return Ok(messages);
}

// Message deletion

/// Deletes the message with the given `row_id` from the database, if it's present.
pub fn delete_message(
    row_id: i64, auth_token: &str, pool: &storage::DatabaseConnectionPool,
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
        let raw_query =
            format!("SELECT public_key FROM {} WHERE rowid = (?1)", storage::MESSAGES_TABLE);
        let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
        let rows = match query.query_map(params![row_id], |row| Ok(row.get(0)?)) {
            Ok(rows) => rows,
            Err(e) => {
                error!("Couldn't delete message due to error: {}.", e);
                return Err(warp::reject::custom(Error::DatabaseFailedInternally));
            }
        };
        let public_keys: Vec<String> = rows.filter_map(|result| result.ok()).collect();
        public_keys.get(0).map(|s| s.to_string())
    };
    let sender = sender_option.ok_or(warp::reject::custom(Error::DatabaseFailedInternally))?;
    if !is_moderator(&requesting_public_key, pool)? && requesting_public_key != sender {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Delete the message if it's present
    let stmt = format!("DELETE FROM {} WHERE rowid = (?1)", storage::MESSAGES_TABLE);
    let count = match tx.execute(&stmt, params![row_id]) {
        Ok(count) => count,
        Err(e) => {
            error!("Couldn't delete message due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Update the deletions table if needed
    if count > 0 {
        let stmt = format!("INSERT INTO {} (id) VALUES (?1)", storage::DELETED_MESSAGES_TABLE);
        match tx.execute(&stmt, params![row_id]) {
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
) -> Result<Vec<i64>, Rejection> {
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
    let raw_query: String;
    if query_params.get("from_server_id").is_some() {
        raw_query = format!(
            "SELECT id FROM {} WHERE rowid > (?1) ORDER BY rowid ASC LIMIT (?2)",
            storage::DELETED_MESSAGES_TABLE
        );
    } else {
        raw_query = format!(
            "SELECT id FROM {} ORDER BY rowid DESC LIMIT (?2)",
            storage::DELETED_MESSAGES_TABLE
        );
    }
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![from_server_id, limit], |row| Ok(row.get(0)?)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let ids: Vec<i64> = rows.filter_map(|result| result.ok()).collect();
    // Return the IDs
    return Ok(ids);
}

// Moderation

// Not publicly exposed.
pub async fn add_moderator(
    body: models::ChangeModeratorRequestBody,
) -> Result<Response, Rejection> {
    // Get a database connection
    let pool = storage::pool_by_room_id(&body.room_id);
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the moderator
    let stmt = format!("INSERT INTO {} (public_key) VALUES (?1)", storage::MODERATORS_TABLE);
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

// Not publicly exposed.
pub async fn delete_moderator(
    body: models::ChangeModeratorRequestBody,
) -> Result<Response, Rejection> {
    // Get a database connection
    let pool = storage::pool_by_room_id(&body.room_id);
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the moderator
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::MODERATORS_TABLE);
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
    let stmt = format!("INSERT INTO {} (public_key) VALUES (?1)", storage::BLOCK_LIST_TABLE);
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
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::BLOCK_LIST_TABLE);
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
    let raw_query = format!("SELECT public_key FROM {}", storage::TOKENS_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| Ok(row.get(0)?)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let public_keys: Vec<String> = rows.filter_map(|result| result.ok()).collect();
    let public_key_count = public_keys.len();
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        member_count: usize,
    }
    let response =
        Response { status_code: StatusCode::OK.as_u16(), member_count: public_key_count };
    return Ok(warp::reply::json(&response).into_response());
}

pub fn compact_poll(
    request_bodies: Vec<models::CompactPollRequestBody>,
) -> Result<Response, Rejection> {
    let mut response_bodies: Vec<models::CompactPollResponseBody> = vec![];
    for request_body in request_bodies {
        // Unwrap the request body
        let models::CompactPollRequestBody {
            room_id,
            auth_token,
            from_message_server_id,
            from_deletion_server_id,
        } = request_body;
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

// Utilities

fn get_pending_tokens(
    public_key: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<(i64, Vec<u8>)>, Rejection> {
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let raw_query = format!(
        "SELECT timestamp, token FROM {} WHERE public_key = (?1) AND timestamp > (?2)",
        storage::PENDING_TOKENS_TABLE
    );
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
    let raw_query = format!("SELECT public_key FROM {}", storage::MODERATORS_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| Ok(row.get(0)?)) {
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
    let raw_query = format!("SELECT public_key FROM {}", storage::BLOCK_LIST_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| Ok(row.get(0)?)) {
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
    let public_keys = get_banned_public_keys_vector(&pool)?;
    return Ok(public_keys.contains(&public_key.to_owned()));
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
    let raw_query = format!("SELECT public_key FROM {} WHERE token = (?1)", storage::TOKENS_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![auth_token], |row| Ok(row.get(0)?)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let public_keys: Vec<String> = rows.filter_map(|result| result.ok()).collect();
    // Return
    return Ok(public_keys.get(0).map(|s| s.to_string()));
}

fn has_authorization_level(
    auth_token: &str, level: AuthorizationLevel, pool: &storage::DatabaseConnectionPool,
) -> Result<(bool, String), Rejection> {
    // Check that we have a public key associated with the given auth token
    let public_key_option = get_public_key_for_auth_token(auth_token, pool)?;
    let public_key = public_key_option.ok_or(warp::reject::custom(Error::NoAuthToken))?;
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
