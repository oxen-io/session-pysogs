use regex::Regex;
use rusqlite::params;
use warp::{Rejection, http::StatusCode};

use super::models;
use super::storage;

#[derive(Debug)]
pub struct UnauthorizedError;
impl warp::reject::Reject for UnauthorizedError { }

/// Inserts the given `message` into the database if it's valid.
pub async fn insert_message(mut message: models::Message, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Validate the message
    if !message.is_valid() { return Err(warp::reject::custom(models::ValidationError)); }

    // TODO: Check that the requesting user isn't banned

    // Get a connection and open a transaction
    let mut conn = storage::conn(&pool)?;
    let tx = storage::tx(&mut conn)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (text) VALUES (?1)", storage::MESSAGES_TABLE);
    storage::exec(&stmt, params![ message.text ], &tx)?;
    let id = tx.last_insert_rowid();
    message.server_id = Some(id);
    // Commit
    tx.commit(); // TODO: Unwrap
    // Return
    return Ok(warp::reply::json(&message));
}

/// Returns either the last `limit` messages or all messages since `from_server_id, limited to `limit`.
pub async fn get_messages(options: models::QueryOptions, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Get a database connection
    let conn = storage::conn(&pool)?;
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
    return Ok(warp::reply::json(&messages));
}

/// Deletes the message with the given `row_id` from the database, if it's present.
pub async fn delete_message(row_id: i64, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Get a connection and open a transaction
    let mut conn = storage::conn(&pool)?;
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
    return Ok(StatusCode::OK);
}

/// Returns either the last `limit` deleted messages or all deleted messages since `from_server_id, limited to `limit`.
pub async fn get_deleted_messages(options: models::QueryOptions, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Get a database connection
    let conn = storage::conn(&pool)?;
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
    return Ok(warp::reply::json(&ids));
}

/// Returns the full list of moderators.
pub async fn get_moderators(pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    let public_keys = get_moderators_vector(&pool)?;
    return Ok(warp::reply::json(&public_keys));
}

/// Bans the given `public_key`, if the requesting user is a moderator.
pub async fn ban(public_key: String, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { return Err(warp::reject::custom(models::ValidationError)); }

    // TODO: Authentication

    // Get a connection and open a transaction
    let mut conn = storage::conn(&pool)?;
    let tx = storage::tx(&mut conn)?;
    // Insert the message
    let stmt = format!("INSERT INTO {} (public_key) VALUES (?1)", storage::BLOCK_LIST_TABLE);
    storage::exec(&stmt, params![ public_key ], &tx)?;
    // Commit
    tx.commit(); // TODO: Unwrap
    // Return
    return Ok(warp::reply::reply());
}

/// Unbans the given `public_key`, if the requesting user is a moderator.
pub async fn unban(public_key: String, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Validate the public key
    if !is_valid_public_key(&public_key) { return Err(warp::reject::custom(models::ValidationError)); }

    // TODO: Authentication

    // Get a connection and open a transaction
    let mut conn = storage::conn(&pool)?;
    let tx = storage::tx(&mut conn)?;
    // Insert the message
    let stmt = format!("DELETE FROM {} WHERE public_key = (?1)", storage::BLOCK_LIST_TABLE);
    storage::exec(&stmt, params![ public_key ], &tx)?;
    // Commit
    tx.commit(); // TODO: Unwrap
    // Return
    return Ok(warp::reply::reply());
}

// Utilities

pub fn get_moderators_vector(pool: &storage::DatabaseConnectionPool) -> Result<Vec<String>, Rejection> {
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

pub fn is_moderator(public_key: &str, pool: &storage::DatabaseConnectionPool) -> Result<bool, Rejection> {
    let public_keys = get_moderators_vector(&pool)?;
    return Ok(public_keys.contains(&public_key.to_owned()));
}

pub fn is_valid_public_key(public_key: &str) -> bool {
    let re = Regex::new(r"^[0-9a-fA-F]+$").unwrap(); // Force
    return re.is_match(public_key);
}