use std::fs;
use std::io::prelude::*;

use chrono;
use rusqlite::params;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warp::{Rejection, http::StatusCode, reply::Reply, reply::Response};

use super::crypto;
use super::errors::Error;
use super::models;
use super::rpc;
use super::storage;

enum AuthorizationLevel {
    Basic, 
    Moderator
}

// Files

pub async fn store_file(base64_encoded_bytes: &str, pool: &storage:: DatabaseConnectionPool) -> Result<Response, Rejection> {
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
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    let stmt = format!("INSERT INTO {} (id, timestamp) VALUES (?1, ?2)", storage::FILES_TABLE);
    let _ = match tx.execute(&stmt, params![ id, now ]) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't insert file record due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Write to file
    let mut pos = 0;
    let mut buffer = match fs::File::create(format!("files/{}", &id)) {
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
    return Ok(warp::reply::json(&id).into_response());
}

pub async fn get_file(id: &str) -> Result<String, Rejection> { // Doesn't return a response directly for testing purposes
    // Check that the ID is a valid UUID
    match Uuid::parse_str(id) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't parse UUID from: {} due to error: {}.", id, e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Try to read the file
    let bytes = match fs::read(format!("files/{}", id)) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Couldn't read file due to error: {}.", e);
            return Err(warp::reject::custom(Error::ValidationFailed));
        }
    };
    // Base64 encode the result
    let base64_encoded_bytes = base64::encode(bytes);
    // Return
    return Ok(base64_encoded_bytes);
}

// Authentication

pub async fn get_auth_token_challenge(hex_public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(hex_public_key) { 
        println!("Ignoring challenge request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Convert the public key to bytes and cut off the version byte
    let public_key: Vec<u8> = hex::decode(hex_public_key).unwrap()[1..].to_vec();
    // Generate an ephemeral key pair
    let (ephemeral_private_key, ephemeral_public_key) = crypto::generate_ephemeral_x25519_key_pair().await;
    // Generate a symmetric key from the requesting user's public key and the ephemeral private key
    let symmetric_key = crypto::get_x25519_symmetric_key(&public_key, &ephemeral_private_key).await?;
    // Generate a random token
    let mut token = [0u8; 48];
    thread_rng().fill(&mut token[..]);
    // Store the (pending) token
    // Note that a given public key can have multiple pending tokens
    {
        let now = chrono::Utc::now().timestamp();
        let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
        let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
        let stmt = format!("INSERT INTO {} (public_key, timestamp, token) VALUES (?1, ?2, ?3)", storage::PENDING_TOKENS_TABLE);
        let _ = match tx.execute(&stmt, params![ hex_public_key, now, token.to_vec() ]) {
            Ok(rows) => rows,
            Err(e) => {
                println!("Couldn't insert pending token due to error: {}.", e);
                return Err(warp::reject::custom(Error::DatabaseFailedInternally));
            }
        };
        tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    };
    // Encrypt the token with the symmetric key
    let ciphertext = crypto::encrypt_aes_gcm(&token, &symmetric_key).await?;
    // Return
    #[derive(Deserialize, Serialize, Debug)]
    struct JSON {
        ciphertext: String,
        ephemeral_public_key: String
    }
    let json = JSON { ciphertext : base64::encode(ciphertext), ephemeral_public_key : base64::encode(ephemeral_public_key.to_bytes()) };
    return Ok(warp::reply::json(&json).into_response());
}

pub async fn claim_auth_token(public_key: &str, token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring claim token request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Validate the token
    let token = token.ok_or(warp::reject::custom(Error::ValidationFailed))?;
    if hex::decode(&token).is_err() { 
        println!("Ignoring claim token request for invalid token.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Get a database connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Get the pending tokens for the given public key
    let pending_tokens: Vec<(i64, Vec<u8>)> = {
        let raw_query = format!("SELECT timestamp, token FROM {} WHERE public_key = (?1) AND timestamp > (?2)", storage::PENDING_TOKENS_TABLE);
        let mut query = tx.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
        let now = chrono::Utc::now().timestamp();
        let expiration = now - storage::PENDING_TOKEN_EXPIRATION;
        let rows = match query.query_map(params![ public_key, expiration ], |row| {
            Ok((row.get(0)?, row.get(1)?))
        }) {
            Ok(rows) => rows,
            Err(e) => {
                println!("Couldn't get pending tokens due to error: {}.", e);
                return Err(warp::reject::custom(Error::DatabaseFailedInternally));
            }
        };
        rows.filter_map(|result| result.ok()).collect()
    };
    // Check that the token being claimed is in fact one of the pending tokens
    let claim = hex::decode(token).unwrap(); // Safe because we validated it above
    let index = pending_tokens.iter().position(|(_, pending_token)| *pending_token == claim).ok_or_else(|| Error::Unauthorized)?;
    let token = &pending_tokens[index].1;
    // Delete all pending tokens for the given public key
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::PENDING_TOKENS_TABLE);
    match tx.execute(&stmt, params![ public_key ]) {
        Ok(_) => (),
        Err(e) => println!("Couldn't delete pending tokens due to error: {}.", e) // It's not catastrophic if this fails
    };
    // Store the claimed token
    let stmt = format!("INSERT OR REPLACE INTO {} (public_key, token) VALUES (?1, ?2)", storage::TOKENS_TABLE);
    match tx.execute(&stmt, params![ public_key, hex::encode(token) ]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't insert token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    // Commit
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Return
    return Ok(StatusCode::OK.into_response());
}

pub async fn delete_auth_token(auth_token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, requesting_public_key) = has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level { return Err(warp::reject::custom(Error::Unauthorized)); }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Delete the token
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::TOKENS_TABLE);
    match tx.execute(&stmt, params![ requesting_public_key ]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't delete token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Commit
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Return
    return Ok(StatusCode::OK.into_response());
}

// Message sending & receiving

/// Inserts the given `message` into the database if it's valid.
pub async fn insert_message(mut message: models::Message, auth_token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the message
    if !message.is_valid() { 
        println!("Ignoring invalid message.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Check authorization level
    let (has_authorization_level, requesting_public_key) = has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level { return Err(warp::reject::custom(Error::Unauthorized)); }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (public_key, text) VALUES (?1, ?2)", storage::MESSAGES_TABLE);
    match tx.execute(&stmt, params![ &requesting_public_key, message.text ]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't insert message due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    let id = tx.last_insert_rowid();
    message.server_id = Some(id);
    // Commit
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Return
    return Ok(warp::reply::json(&message).into_response());
}

/// Returns either the last `limit` messages or all messages since `from_server_id, limited to `limit`.
pub async fn get_messages(options: rpc::QueryOptions, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Unwrap parameters
    let from_server_id = options.from_server_id.unwrap_or(0);
    let limit = options.limit.unwrap_or(256); // Never return more than 256 messages at once
    // Query the database
    let raw_query: String;
    if options.from_server_id.is_some() {
        raw_query = format!("SELECT id, text FROM {} WHERE rowid > (?1) LIMIT (?2)", storage::MESSAGES_TABLE);
    } else {
        raw_query = format!("SELECT id, text FROM {} ORDER BY rowid DESC LIMIT (?2)", storage::MESSAGES_TABLE);
    }
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![ from_server_id, limit ], |row| {
        Ok(models::Message { server_id : row.get(0)?, text : row.get(1)? })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't get messages due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let messages: Vec<models::Message> = rows.filter_map(|result| result.ok()).collect();
    // Return the messages
    return Ok(warp::reply::json(&messages).into_response());
}

// Message deletion

/// Deletes the message with the given `row_id` from the database, if it's present.
pub async fn delete_message(row_id: i64, auth_token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Check authorization level
    let (has_authorization_level, requesting_public_key) = has_authorization_level(auth_token, AuthorizationLevel::Basic, pool).await?;
    if !has_authorization_level { return Err(warp::reject::custom(Error::Unauthorized)); }
    // Check that the requesting user is either the sender of the message or a moderator
    let sender_option: Option<String> = {
        let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
        let raw_query = format!("SELECT public_key FROM {} WHERE rowid = (?1)", storage::MESSAGES_TABLE);
        let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
        let rows = match query.query_map(params![ row_id ], |row| {
            Ok(row.get(0)?)
        }) {
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
    if !is_moderator(&requesting_public_key, pool).await? && requesting_public_key != sender { return Err(warp::reject::custom(Error::Unauthorized)); }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Delete the message if it's present
    let stmt = format!("DELETE FROM {} WHERE rowid = (?1)", storage::MESSAGES_TABLE);
    let count = match tx.execute(&stmt, params![ row_id ]) {
        Ok(count) => count,
        Err(e) => {
            println!("Couldn't delete message due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Update the deletions table if needed
    if count > 0 {
        let stmt = format!("INSERT INTO {} (id) VALUES (?1)", storage::DELETED_MESSAGES_TABLE);
        match tx.execute(&stmt, params![ row_id ]) {
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
    return Ok(StatusCode::OK.into_response());
}

/// Returns either the last `limit` deleted messages or all deleted messages since `from_server_id, limited to `limit`.
pub async fn get_deleted_messages(options: rpc::QueryOptions, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Unwrap parameters
    let from_server_id = options.from_server_id.unwrap_or(0);
    let limit = options.limit.unwrap_or(256); // Never return more than 256 deleted messages at once
    // Query the database
    let raw_query: String;
    if options.from_server_id.is_some() {
        raw_query = format!("SELECT id FROM {} WHERE rowid > (?1) LIMIT (?2)", storage::DELETED_MESSAGES_TABLE);
    } else {
        raw_query = format!("SELECT id FROM {} ORDER BY rowid DESC LIMIT (?2)", storage::DELETED_MESSAGES_TABLE);
    }
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![ from_server_id, limit ], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let ids: Vec<i64> = rows.filter_map(|result| result.ok()).collect();
    // Return the IDs
    return Ok(warp::reply::json(&ids).into_response());
}

// Moderation

/// Returns the full list of moderators.
pub async fn get_moderators(pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    let public_keys = get_moderators_vector(pool).await?;
    return Ok(warp::reply::json(&public_keys).into_response());
}

/// Bans the given `public_key` if the requesting user is a moderator.
pub async fn ban(public_key: &str, auth_token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring ban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Check authorization level
    let (has_authorization_level, _) = has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool).await?;
    if !has_authorization_level { return Err(warp::reject::custom(Error::Unauthorized)); }
    // Don't double ban public keys
    if is_banned(&public_key, pool).await? { return Ok(StatusCode::OK.into_response()); }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (public_key) VALUES (?1)", storage::BLOCK_LIST_TABLE);
    match tx.execute(&stmt, params![ public_key ]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't ban public key due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Commit
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Return
    return Ok(StatusCode::OK.into_response());
}

/// Unbans the given `public_key` if the requesting user is a moderator.
pub async fn unban(public_key: &str, auth_token: Option<String>, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring unban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Check authorization level
    let (has_authorization_level, _) = has_authorization_level(auth_token, AuthorizationLevel::Moderator, pool).await?;
    if !has_authorization_level { return Err(warp::reject::custom(Error::Unauthorized)); }
    // Don't double unban public keys
    if !is_banned(&public_key, pool).await? { return Ok(StatusCode::OK.into_response()); }
    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::BLOCK_LIST_TABLE);
    match tx.execute(&stmt, params![ public_key ]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't unban public key due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Commit
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
    // Return
    return Ok(StatusCode::OK.into_response());
}

/// Returns the full list of banned public keys.
pub async fn get_banned_public_keys(pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    let public_keys = get_banned_public_keys_vector(pool).await?;
    return Ok(warp::reply::json(&public_keys).into_response());
}

// General

pub async fn get_member_count(pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT public_key FROM {}", storage::TOKENS_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let public_keys: Vec<String> = rows.filter_map(|result| result.ok()).collect();
    let public_key_count = public_keys.len();
    // Return
    return Ok(warp::reply::json(&public_key_count).into_response());
}

// Utilities

async fn get_moderators_vector(pool: &storage::DatabaseConnectionPool) -> Result<Vec<String>, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT public_key FROM {}", storage::MODERATORS_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    return Ok(rows.filter_map(|result| result.ok()).collect());
}

async fn is_moderator(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<bool, Rejection> {
    let public_keys = get_moderators_vector(&pool).await?;
    return Ok(public_keys.contains(&public_key.to_owned()));
}

async fn get_banned_public_keys_vector(pool: &storage::DatabaseConnectionPool) -> Result<Vec<String>, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT public_key FROM {}", storage::BLOCK_LIST_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    // Return
    return Ok(rows.filter_map(|result| result.ok()).collect());
}

async fn is_banned(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<bool, Rejection> {
    let public_keys = get_banned_public_keys_vector(&pool).await?;
    return Ok(public_keys.contains(&public_key.to_owned()));
}

fn is_valid_public_key(public_key: &str) -> bool {
    // Check that it's a valid hex encoding
    if hex::decode(public_key).is_err() { return false; }
    // Check that it's the right length
    if public_key.len() != 66 { return false } // The version byte + 32 bytes of random data
    // It appears to be a valid public key
    return true
}

async fn get_public_key_for_auth_token(auth_token: &str, pool: &storage::DatabaseConnectionPool) -> Result<Option<String>, Rejection> {
    // Get a database connection
    let conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT public_key FROM {} WHERE token = (?1)", storage::TOKENS_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![ auth_token ], |row| {
        Ok(row.get(0)?)
    }) {
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

async fn has_authorization_level(auth_token: Option<String>, level: AuthorizationLevel, pool: &storage::DatabaseConnectionPool) -> Result<(bool, String), Rejection> {
    // Check that the auth token is present
    let auth_token = auth_token.ok_or(warp::reject::custom(Error::Unauthorized))?;
    // Check that we have a public key associated with the given auth token
    let public_key_option = get_public_key_for_auth_token(&auth_token, pool).await?;
    let public_key = public_key_option.ok_or(warp::reject::custom(Error::Unauthorized))?;
    // Check that the given public key isn't banned
    if is_banned(&public_key, pool).await? { return Err(warp::reject::custom(Error::Unauthorized)); }
    // If needed, check that the given public key is a moderator
    match level {
        AuthorizationLevel::Basic => return Ok((true, public_key)),
        AuthorizationLevel::Moderator => {
            if !is_moderator(&public_key, pool).await? { return Err(warp::reject::custom(Error::Unauthorized)); }
            return Ok((true, public_key));
        }
    };
}
