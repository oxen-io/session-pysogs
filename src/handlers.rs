use chrono;
use rusqlite::params;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use warp::{Rejection, http::StatusCode, reply::Reply, reply::Response};

use super::crypto;
use super::errors::Error;
use super::models;
use super::rpc;
use super::storage;

/// The period after which a pending token is expired.
const TOKEN_EXPIRATION: i64 = 10 * 60;

// TODO: Expire tokens after 10 minutes

pub async fn get_challenge(hex_public_key: String, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&hex_public_key) { 
        println!("Ignoring challenge request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Convert the public key to bytes and cut off the version byte
    let public_key: Vec<u8> = hex::decode(&hex_public_key).unwrap()[1..].to_vec();
    // Generate an ephemeral key pair
    let (ephemeral_private_key, ephemeral_public_key) = crypto::generate_ephemeral_x25519_key_pair().await;
    // Generate a symmetric key from the requesting user's public key and the ephemeral private key
    let symmetric_key = crypto::get_x25519_symmetric_key(&public_key, &ephemeral_private_key).await?;
    // Generate a random token
    let mut token = [0u8; 48];
    thread_rng().fill(&mut token[..]);
    // Store the (pending) token
    // A given public key can have multiple pending tokens
    let now = chrono::Utc::now().timestamp();
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    let stmt = format!("INSERT INTO {} (public_key, timestamp, token) VALUES (?1, ?2, ?3)", storage::PENDING_TOKENS_TABLE);
    match tx.execute(&stmt, params![ hex_public_key, now, token.to_vec() ]) {
        Ok(_) => (),
        Err(e) => {
            println!("Couldn't insert pending token due to error: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    }
    tx.commit().map_err(|_| Error::DatabaseFailedInternally)?;
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

pub async fn claim_token(public_key: String, token: String, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring claim token request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }
    // Validate the token
    if !is_valid_public_key(&token) { 
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
        let expiration = now - TOKEN_EXPIRATION;
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
    match tx.execute(&stmt, params![ public_key, token ]) {
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

/// Inserts the given `message` into the database if it's valid.
pub async fn insert_message(mut message: models::Message, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the message
    if !message.is_valid() { 
        println!("Ignoring invalid message.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }

    // TODO: Check that the requesting user isn't banned

    // Get a connection and open a transaction
    let mut conn = pool.get().map_err(|_| Error::DatabaseFailedInternally)?;
    let tx = conn.transaction().map_err(|_| Error::DatabaseFailedInternally)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (text) VALUES (?1)", storage::MESSAGES_TABLE);
    match tx.execute(&stmt, params![ message.text ]) {
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

/// Deletes the message with the given `row_id` from the database, if it's present.
pub async fn delete_message(row_id: i64, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    
    // TODO: Check that the requesting user has permission (either it's their own message or they're a moderator)

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

/// Returns the full list of moderators.
pub async fn get_moderators(pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    let public_keys = get_moderators_vector(pool).await?;
    return Ok(warp::reply::json(&public_keys).into_response());
}

/// Bans the given `public_key`, if the requesting user is a moderator.
pub async fn ban(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring ban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }

    // TODO: Check that the requesting user is a moderator

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

/// Unbans the given `public_key`, if the requesting user is a moderator.
pub async fn unban(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring unban request for invalid public key.");
        return Err(warp::reject::custom(Error::ValidationFailed)); 
    }

    // TODO: Check that the requesting user is a moderator

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

    // TODO: Check that the requesting user is a moderator

    let public_keys = get_banned_public_keys_vector(pool).await?;
    return Ok(warp::reply::json(&public_keys).into_response());
}

pub async fn get_member_count(pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    let member_count = 5; // TODO: Implement
    return Ok(warp::reply::json(&member_count).into_response());
}

// Utilities

pub async fn get_moderators_vector(pool: &storage::DatabaseConnectionPool) -> Result<Vec<String>, Rejection> {
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

pub async fn is_moderator(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<bool, Rejection> {
    let public_keys = get_moderators_vector(&pool).await?;
    return Ok(public_keys.contains(&public_key.to_owned()));
}

pub async fn get_banned_public_keys_vector(pool: &storage::DatabaseConnectionPool) -> Result<Vec<String>, Rejection> {
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

pub async fn is_banned(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<bool, Rejection> {
    let public_keys = get_banned_public_keys_vector(&pool).await?;
    return Ok(public_keys.contains(&public_key.to_owned()));
}

pub fn is_valid_public_key(public_key: &str) -> bool {
    // Check that it's a valid hex encoding
    if hex::decode(public_key).is_err() { return false; }
    // Check that it's the right length
    if public_key.len() != 66 { return false } // The version byte + 32 bytes of random data
    // It appears to be a valid public key
    return true
}