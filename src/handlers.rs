use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::io::prelude::*;
use std::path::Path;

use chrono;
use rand::{thread_rng, Rng};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
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
struct RoomInfo {
    id: String,
    name: String,
    image_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenericStringResponse {
    pub status_code: u16,
    pub result: String,
}

// Rooms

// Currently not exposed
pub async fn create_room(id: &str, name: &str) -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the room
    let stmt = format!("REPLACE INTO {} (id, name) VALUES (?1, ?2)", storage::MAIN_TABLE);
    match conn.execute(&stmt, params![id, name]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't create room due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Set up the database
    storage::create_database_if_needed(id);
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

pub async fn get_room(room_id: &str) -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Get the room info if possible
    let raw_query =
        format!("SELECT id, name, image_id FROM {} where id = (?1)", storage::MAIN_TABLE);
    let room = match conn.query_row(&raw_query, params![room_id], |row| {
        Ok(RoomInfo { id: row.get(0)?, name: row.get(1)?, image_id: row.get(2).ok() })
    }) {
        Ok(info) => info,
        Err(_) => return Err(warp::reject::custom(Error::NoSuchRoom)),
    };
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        room: RoomInfo,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), room };
    return Ok(warp::reply::json(&response).into_response());
}

pub async fn get_all_rooms() -> Result<Response, Rejection> {
    // Get a connection
    let pool = &storage::MAIN_POOL;
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Get the room info if possible
    let raw_query = format!("SELECT id, name, image_id FROM {}", storage::MAIN_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| {
        Ok(RoomInfo { id: row.get(0)?, name: row.get(1)?, image_id: row.get(2).ok() })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't get rooms due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let rooms: Vec<RoomInfo> = rows.filter_map(|result| result.ok()).collect();
    // Return
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        rooms: Vec<RoomInfo>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), rooms };
    return Ok(warp::reply::json(&response).into_response());
}

// Files

pub async fn store_file(
    base64_encoded_bytes: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Parse bytes
    let bytes = match base64::decode(base64_encoded_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Couldn't parse bytes from invalid base64 encoding due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Generate UUID
    let id = Uuid::new_v4();
    let mut buffer = Uuid::encode_buffer();
    let id: String = id.to_simple().encode_lower(&mut buffer).to_string();
    // Update the database
    // We do this * before * storing the actual file, so that in case something goes
    // wrong we're not left with files that'll never be pruned.
    let now = chrono::Utc::now().timestamp();
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let stmt = format!("INSERT INTO {} (id, timestamp) VALUES (?1, ?2)", storage::FILES_TABLE);
    let _ = match conn.execute(&stmt, params![id, now]) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't insert file record due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Write to file
    let mut pos = 0;
    let raw_path = format!("files/{}", &id);
    let path = Path::new(&raw_path);
    let mut buffer = match fs::File::create(path) {
        Ok(buffer) => buffer,
        Err(e) => {
            println!("Couldn't store file due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    while pos < bytes.len() {
        let count = match buffer.write(&bytes[pos..]) {
            Ok(count) => count,
            Err(e) => {
                println!("Couldn't store file due to error: {}.", e);
                return Err(warp::reject::custom(Error::DatabaseFailedInternally));
            }
        };
        pos += count;
    }
    // Return
    let json = GenericStringResponse { status_code: StatusCode::OK.as_u16(), result: id };
    return Ok(warp::reply::json(&json).into_response());
}

pub async fn get_file(
    id: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<GenericStringResponse, Rejection> {
    // Doesn't return a response directly for testing purposes
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Check that the ID is a valid UUID
    match Uuid::parse_str(id) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't parse UUID from: {} due to error: {}.", id, e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Try to read the file
    let raw_path = format!("files/{}", id);
    let path = Path::new(&raw_path);
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Couldn't read file due to error: {}.", e);
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

// Authentication

pub async fn get_auth_token_challenge(
    query_params: HashMap<String, String>, pool: &storage::DatabaseConnectionPool,
) -> Result<models::Challenge, Rejection> {
    // Doesn't return a response directly for testing purposes
    // Get the public key
    let hex_public_key =
        query_params.get("public_key").ok_or(warp::reject::custom(Error::InvalidRpcCall))?;
    // Validate the public key
    if !is_valid_public_key(hex_public_key) {
        println!("Ignoring challenge request for invalid public key: {}.", hex_public_key);
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Convert the public key to bytes and cut off the version byte
    let public_key: [u8; 32] = hex::decode(hex_public_key).unwrap()[1..].try_into().unwrap(); // Safe because we know it has a length of 32 at this point
                                                                                              // Generate an ephemeral key pair
    let (ephemeral_private_key, ephemeral_public_key) = crypto::generate_x25519_key_pair().await;
    // Generate a symmetric key from the requesting user's public key and the ephemeral private key
    let symmetric_key =
        crypto::get_x25519_symmetric_key(&public_key, &ephemeral_private_key).await?;
    // Generate a random token
    let mut token = [0u8; 48];
    thread_rng().fill(&mut token[..]);
    // Store the (pending) token
    // Note that a given public key can have multiple pending tokens
    let now = chrono::Utc::now().timestamp();
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let stmt = format!(
        "INSERT INTO {} (public_key, timestamp, token) VALUES (?1, ?2, ?3)",
        storage::PENDING_TOKENS_TABLE
    );
    let _ = match conn.execute(&stmt, params![hex_public_key, now, token.to_vec()]) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't insert pending token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Encrypt the token with the symmetric key
    let ciphertext = crypto::encrypt_aes_gcm(&token, &symmetric_key).await?;
    // Return
    return Ok(models::Challenge {
        ciphertext: base64::encode(ciphertext),
        ephemeral_public_key: base64::encode(ephemeral_public_key.to_bytes()),
    });
}

pub async fn claim_auth_token(
    public_key: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) {
        println!("Ignoring claim token request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Validate the token
    if hex::decode(auth_token).is_err() {
        println!("Ignoring claim token request for invalid token.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Get the pending tokens for the given public key
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
            println!("Couldn't get pending tokens due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let pending_tokens: Vec<(i64, Vec<u8>)> = rows.filter_map(|result| result.ok()).collect();
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
            println!("Couldn't insert token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Delete all pending tokens for the given public key
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::PENDING_TOKENS_TABLE);
    match conn.execute(&stmt, params![public_key]) {
        Ok(_) => (),
        Err(e) => println!("Couldn't delete pending tokens due to error: {}.", e), // It's not catastrophic if this fails
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

pub async fn delete_auth_token(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, requesting_public_key) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
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
            println!("Couldn't delete token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

// Message sending & receiving

/// Inserts the given `message` into the database if it's valid.
pub async fn insert_message(
    mut message: models::Message, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the message
    if !message.is_valid() {
        println!("Ignoring invalid message.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Check authorization level
    let (has_authorization_level, requesting_public_key) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!(
        "INSERT INTO {} (public_key, data, signature) VALUES (?1, ?2, ?3)",
        storage::MESSAGES_TABLE
    );
    match tx.execute(&stmt, params![&requesting_public_key, message.data, message.signature]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't insert message due to error: {}.", e);
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
pub async fn get_messages(
    query_params: HashMap<String, String>, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
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
        raw_query = format!("SELECT id, public_key, data, signature FROM {} WHERE rowid > (?1) ORDER BY rowid ASC LIMIT (?2)", storage::MESSAGES_TABLE);
    } else {
        raw_query = format!(
            "SELECT id, public_key, data, signature FROM {} ORDER BY rowid DESC LIMIT (?2)",
            storage::MESSAGES_TABLE
        );
    }
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![from_server_id, limit], |row| {
        Ok(models::Message {
            server_id: row.get(0)?,
            public_key: row.get(1)?,
            data: row.get(2)?,
            signature: row.get(3)?,
        })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't get messages due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let messages: Vec<models::Message> = rows.filter_map(|result| result.ok()).collect();
    // Return the messages
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        messages: Vec<models::Message>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), messages };
    return Ok(warp::reply::json(&response).into_response());
}

// Message deletion

/// Deletes the message with the given `row_id` from the database, if it's present.
pub async fn delete_message(
    row_id: i64, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, requesting_public_key) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
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
                println!("Couldn't delete message due to error: {}.", e);
                return Err(warp::reject::custom(Error::DatabaseFailedInternally));
            }
        };
        let public_keys: Vec<String> = rows.filter_map(|result| result.ok()).collect();
        public_keys.get(0).map(|s| s.to_string())
    };
    let sender = sender_option.ok_or(warp::reject::custom(Error::DatabaseFailedInternally))?;
    if !is_moderator(&requesting_public_key, pool).await? && requesting_public_key != sender {
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
            println!("Couldn't delete message due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Update the deletions table if needed
    if count > 0 {
        let stmt = format!("INSERT INTO {} (id) VALUES (?1)", storage::DELETED_MESSAGES_TABLE);
        match tx.execute(&stmt, params![row_id]) {
            Ok(_) => (),
            Err(e) => {
                println!("Couldn't delete message due to error: {}.", e);
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
pub async fn get_deleted_messages(
    query_params: HashMap<String, String>, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
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
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let ids: Vec<i64> = rows.filter_map(|result| result.ok()).collect();
    // Return the IDs
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        ids: Vec<i64>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), ids };
    return Ok(warp::reply::json(&response).into_response());
}

// Moderation

/// Returns the full list of moderators.
pub async fn get_moderators(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Return
    let public_keys = get_moderators_vector(pool).await?;
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        moderators: Vec<String>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), moderators: public_keys };
    return Ok(warp::reply::json(&response).into_response());
}

/// Bans the given `public_key` if the requesting user is a moderator.
pub async fn ban(
    public_key: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) {
        println!("Ignoring ban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool).await?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Don't double ban public keys
    if is_banned(&public_key, pool).await? {
        return Ok(StatusCode::OK.into_response());
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (public_key) VALUES (?1)", storage::BLOCK_LIST_TABLE);
    match conn.execute(&stmt, params![public_key]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't ban public key due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Unbans the given `public_key` if the requesting user is a moderator.
pub async fn unban(
    public_key: &str, auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) {
        println!("Ignoring unban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed));
    }
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool).await?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Don't double unban public keys
    if !is_banned(&public_key, pool).await? {
        return Ok(StatusCode::OK.into_response());
    }
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::BLOCK_LIST_TABLE);
    match conn.execute(&stmt, params![public_key]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't unban public key due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    return Ok(warp::reply::json(&json).into_response());
}

/// Returns the full list of banned public keys.
pub async fn get_banned_public_keys(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // Return
    let public_keys = get_banned_public_keys_vector(pool).await?;
    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        status_code: u16,
        banned_members: Vec<String>,
    }
    let response = Response { status_code: StatusCode::OK.as_u16(), banned_members: public_keys };
    return Ok(warp::reply::json(&response).into_response());
}

// General

pub async fn get_member_count(
    auth_token: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, _) =
        has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
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
            println!("Couldn't query database due to error: {}.", e);
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

// Utilities

async fn get_moderators_vector(
    pool: &storage::DatabaseConnectionPool,
) -> Result<Vec<String>, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT public_key FROM {}", storage::MODERATORS_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| Ok(row.get(0)?)) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    return Ok(rows.filter_map(|result| result.ok()).collect());
}

async fn is_moderator(
    public_key: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<bool, Rejection> {
    let public_keys = get_moderators_vector(&pool).await?;
    return Ok(public_keys.contains(&public_key.to_owned()));
}

async fn get_banned_public_keys_vector(
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
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    return Ok(rows.filter_map(|result| result.ok()).collect());
}

async fn is_banned(
    public_key: &str, pool: &storage::DatabaseConnectionPool,
) -> Result<bool, Rejection> {
    let public_keys = get_banned_public_keys_vector(&pool).await?;
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

async fn get_public_key_for_auth_token(
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
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let public_keys: Vec<String> = rows.filter_map(|result| result.ok()).collect();
    // Return
    return Ok(public_keys.get(0).map(|s| s.to_string()));
}

async fn has_authorization_level(
    auth_token: &str, level: AuthorizationLevel, pool: &storage::DatabaseConnectionPool,
) -> Result<(bool, String), Rejection> {
    // Check that we have a public key associated with the given auth token
    let public_key_option = get_public_key_for_auth_token(auth_token, pool).await?;
    let public_key = public_key_option.ok_or(warp::reject::custom(Error::Unauthorized))?;
    // Check that the given public key isn't banned
    if is_banned(&public_key, pool).await? {
        return Err(warp::reject::custom(Error::Unauthorized));
    }
    // If needed, check that the given public key is a moderator
    match level {
        AuthorizationLevel::Basic => return Ok((true, public_key)),
        AuthorizationLevel::Moderator => {
            if !is_moderator(&public_key, pool).await? {
                return Err(warp::reject::custom(Error::Unauthorized));
            }
            return Ok((true, public_key));
        }
    };
}
