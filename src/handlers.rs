use rusqlite::params;
use warp::{Rejection, http::StatusCode};

use super::models;
use super::storage;

/// Inserts the given `message` into the database if it's valid.
pub async fn insert_message(message: models::Message, db_pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Validate the message
    if !message.is_valid() { return Err(warp::reject::custom(models::ValidationError)); }
    // Get a database connection
    let db_conn = storage::get_db_conn(&db_pool)?;
    // Insert the message
    match db_conn.execute(
        "INSERT INTO messages (text) VALUES (?1)",
        params![message.text],
    ) {
        Ok(_) => return Ok(StatusCode::OK),
        Err(e) => {
            println!("Couldn't insert message due to error: {:?}.", e);
            return Err(warp::reject::custom(storage::DatabaseError)); 
        }
    }
}

/// Returns the last `options.limit` messages from the database.
pub async fn get_messages(options: models::QueryOptions, db_pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    // Get a database connection
    let db_conn = storage::get_db_conn(&db_pool)?;
    // Query the database
    let limit = options.limit.unwrap_or(256); // Never return more than 256 messages at once
    let raw_query = format!("SELECT text FROM messages ORDER BY rowid DESC LIMIT {}", limit); // Get the last `limit` messages
    let mut query = match db_conn.prepare(&raw_query) {
        Ok(query) => query,
        Err(e) => { 
            println!("Couldn't create database query due to error: {:?}.", e);
            return Err(warp::reject::custom(storage::DatabaseError));
        }
    };
    let rows = match query.query_map(params![], |row| {
        Ok(models::Message { text: row.get(0)? })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {:?}.", e);
            return Err(warp::reject::custom(storage::DatabaseError));
        }
    };
    // FIXME: It'd be cleaner to do the below using `collect()`, but the compiler has trouble
    // inferring the item type of `rows` in that case.
    let mut messages: Vec<models::Message> = Vec::new();
    for row in rows {
        match row {
            Ok(message) => messages.push(message),
            Err(e) => {
                println!("Excluding message from response due to database error: {:?}.", e);
                continue;
            }
        }
    }
    // Return the messages
    return Ok(warp::reply::json(&messages));
}