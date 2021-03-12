use regex::Regex;
use rusqlite::params;
use warp::{Rejection, http::StatusCode, reply::Reply, reply::Response};

use super::models;
use super::rpc;
use super::storage;

#[derive(Debug)]
pub struct UnauthorizedError;
impl warp::reject::Reject for UnauthorizedError { }

/// Inserts the given `message` into the database if it's valid.
pub async fn insert_message(mut message: models::Message, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the message
    if !message.is_valid() { 
        println!("Ignoring invalid message.");
        return Err(warp::reject::custom(models::ValidationError)); 
    }

    // TODO: Check that the requesting user isn't banned

    // Get a connection and open a transaction
    let mut conn = storage::conn(pool)?;
    let tx = storage::tx(&mut conn)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (text) VALUES (?1)", storage::MESSAGES_TABLE);
    storage::exec(&stmt, params![ message.text ], &tx)?;
    let id = tx.last_insert_rowid();
    message.server_id = Some(id);
    // Commit
    tx.commit(); // TODO: Unwrap
    // Return
    return Ok(warp::reply::json(&message).into_response());
}

/// Returns either the last `limit` messages or all messages since `from_server_id, limited to `limit`.
pub async fn get_messages(options: rpc::QueryOptions, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Get a database connection
    let conn = storage::conn(pool)?;
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
    let mut query = storage::query(&raw_query, &conn)?;
    let rows = match query.query_map(params![ from_server_id, limit ], |row| {
        Ok(models::Message { server_id : row.get(0)?, text : row.get(1)? })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {:?}.", e);
            return Err(warp::reject::custom(storage::DatabaseError));
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
    let mut conn = storage::conn(pool)?;
    let tx = storage::tx(&mut conn)?;
    // Delete the message if it's present
    let stmt = format!("DELETE FROM {} WHERE rowid = (?1)", storage::MESSAGES_TABLE);
    let count = storage::exec(&stmt, params![ row_id ], &tx)?;
    // Update the deletions table if needed
    if count > 0 {
        let stmt = format!("INSERT INTO {} (id) VALUES (?1)", storage::DELETED_MESSAGES_TABLE);
        storage::exec(&stmt, params![ row_id ], &tx)?;
    }
    // Commit
    tx.commit(); // TODO: Unwrap
    // Return
    return Ok(StatusCode::OK.into_response());
}

/// Returns either the last `limit` deleted messages or all deleted messages since `from_server_id, limited to `limit`.
pub async fn get_deleted_messages(options: rpc::QueryOptions, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Get a database connection
    let conn = storage::conn(pool)?;
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
    let mut query = storage::query(&raw_query, &conn)?;
    let rows = match query.query_map(params![ from_server_id, limit ], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {:?}.", e);
            return Err(warp::reject::custom(storage::DatabaseError));
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
pub async fn ban(public_key: String, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring ban request for invalid public key.");
        return Err(warp::reject::custom(models::ValidationError)); 
    }

    // TODO: Check that the requesting user is a moderator

    // Don't double ban public keys
    if is_banned(&public_key, pool).await? { return Ok(StatusCode::OK.into_response()); }
    // Get a connection and open a transaction
    let mut conn = storage::conn(pool)?;
    let tx = storage::tx(&mut conn)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (public_key) VALUES (?1)", storage::BLOCK_LIST_TABLE);
    storage::exec(&stmt, params![ public_key ], &tx)?;
    // Commit
    tx.commit(); // TODO: Unwrap
    // Return
    return Ok(StatusCode::OK.into_response());
}

/// Unbans the given `public_key`, if the requesting user is a moderator.
pub async fn unban(public_key: String, pool: &storage::DatabaseConnectionPool) -> Result<Response, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { 
        println!("Ignoring unban request for invalid public key.");
        return Err(warp::reject::custom(models::ValidationError)); 
    }

    // TODO: Check that the requesting user is a moderator

    // Don't double unban public keys
    if !is_banned(&public_key, pool).await? { return Ok(StatusCode::OK.into_response()); }
    // Get a connection and open a transaction
    let mut conn = storage::conn(pool)?;
    let tx = storage::tx(&mut conn)?;
    // Insert the message
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::BLOCK_LIST_TABLE);
    storage::exec(&stmt, params![ public_key ], &tx)?;
    // Commit
    tx.commit(); // TODO: Unwrap
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
    let conn = storage::conn(&pool)?;
    // Query the database
    let raw_query = format!("SELECT public_key FROM {}", storage::MODERATORS_TABLE);
    let mut query = storage::query(&raw_query, &conn)?;
    let rows = match query.query_map(params![], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {:?}.", e);
            return Err(warp::reject::custom(storage::DatabaseError));
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
    let conn = storage::conn(&pool)?;
    // Query the database
    let raw_query = format!("SELECT public_key FROM {}", storage::BLOCK_LIST_TABLE);
    let mut query = storage::query(&raw_query, &conn)?;
    let rows = match query.query_map(params![], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {:?}.", e);
            return Err(warp::reject::custom(storage::DatabaseError));
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
    let re = Regex::new(r"^[0-9a-fA-F]+$").unwrap(); // Force
    if !re.is_match(public_key) { return false; };
    // Check that it's the right length
    if public_key.len() != 66 { return false } // The version byte + 32 bytes of random data
    // It appears to be a valid public key
    return true
}