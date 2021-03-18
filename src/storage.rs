use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

use rusqlite::params;
use r2d2_sqlite::SqliteConnectionManager;

use super::errors::Error;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

// Main

const MAIN_TABLE: &str = "main";

lazy_static::lazy_static! {

    static ref MAIN_POOL: DatabaseConnectionPool = {
        let file_name = format!("database.db");
        let db_manager = r2d2_sqlite::SqliteConnectionManager::file(file_name);
        return r2d2::Pool::new(db_manager).unwrap();
    };
}

pub fn create_main_database_if_needed() {
    let pool = &MAIN_POOL;
    let conn = pool.get().unwrap();
    create_main_tables_if_needed(&conn);
}

fn create_main_tables_if_needed(conn: &DatabaseConnection) {
    let main_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        id TEXT PRIMARY KEY,
        name TEXT
    )", MAIN_TABLE);
    conn.execute(&main_table_cmd, params![]).expect("Couldn't create main table.");
}

// Rooms

pub const PENDING_TOKEN_EXPIRATION: i64 = 10 * 60;
pub const TOKEN_EXPIRATION: i64 = 7 * 24 * 60 * 60;
pub const FILE_EXPIRATION: i64 = 60 * 24 * 60 * 60;

pub const MESSAGES_TABLE: &str = "messages";
pub const DELETED_MESSAGES_TABLE: &str = "deleted_messages";
pub const MODERATORS_TABLE: &str = "moderators";
pub const BLOCK_LIST_TABLE: &str = "block_list";
pub const PENDING_TOKENS_TABLE: &str = "pending_tokens";
pub const TOKENS_TABLE: &str = "tokens";
pub const FILES_TABLE: &str = "files";

lazy_static::lazy_static! {

    static ref POOLS: Mutex<HashMap<String, DatabaseConnectionPool>> = Mutex::new(HashMap::new());
}

pub fn pool_by_room_id(room_id: isize) -> Result<DatabaseConnectionPool, Error> {
    // Get a database connection
    let conn = MAIN_POOL.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT name FROM {} WHERE id = (?1)", MAIN_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![ &room_id ], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {}.", e);
            return Err(Error::DatabaseFailedInternally);
        }
    };
    let names: Vec<String> = rows.filter_map(|result| result.ok()).collect();
    if let Some(name) = names.first() {
        return Ok(pool_by_room_name(name));
    } else {
        return Err(Error::DatabaseFailedInternally);
    }
}

pub fn pool_by_room_name(room: &str) -> DatabaseConnectionPool {
    let mut pools = POOLS.lock().unwrap();
    if let Some(pool) = pools.get(room) {
        return pool.clone();
    } else {
        let file_name = format!("{}.db", room);
        let db_manager = r2d2_sqlite::SqliteConnectionManager::file(format!("rooms/{}", file_name));
        let pool = r2d2::Pool::new(db_manager).unwrap();
        pools.insert(room.to_string(), pool);
        return pools[room].clone();
    }
}

pub fn create_database_if_needed(room: &str) {
    let pool = pool_by_room_name(room);
    let conn = pool.get().unwrap();
    create_room_tables_if_needed(&conn);
}

fn create_room_tables_if_needed(conn: &DatabaseConnection) {
    // Messages
    // The `id` field is needed to make `rowid` stable, which is important because otherwise
    // the `id`s in this table won't correspond to those in the deleted messages table
    let messages_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        id INTEGER PRIMARY KEY,
        public_key TEXT,
        text TEXT
    )", MESSAGES_TABLE);
    conn.execute(&messages_table_cmd, params![]).expect("Couldn't create messages table.");
    // Deleted messages
    let deleted_messages_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        id INTEGER PRIMARY KEY
    )", DELETED_MESSAGES_TABLE);
    conn.execute(&deleted_messages_table_cmd, params![]).expect("Couldn't create deleted messages table.");
    // Moderators
    let moderators_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT
    )", MODERATORS_TABLE);
    conn.execute(&moderators_table_cmd, params![]).expect("Couldn't create moderators table.");
    // Block list
    let block_list_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT
    )", BLOCK_LIST_TABLE);
    conn.execute(&block_list_table_cmd, params![]).expect("Couldn't create block list table.");
    // Pending tokens
    // Note that a given public key can have multiple pending tokens
    let pending_tokens_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        public_key STRING,
        timestamp INTEGER,
        token BLOB
    )", PENDING_TOKENS_TABLE);
    conn.execute(&pending_tokens_table_cmd, params![]).expect("Couldn't create pending tokens table.");
    // Tokens
    // The token is stored as hex here (rather than as bytes) because it's more convenient for lookup
    let tokens_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        public_key STRING PRIMARY KEY,
        timestamp INTEGER,
        token TEXT
    )", TOKENS_TABLE);
    conn.execute(&tokens_table_cmd, params![]).expect("Couldn't create tokens table.");
    // Files
    let files_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        id STRING PRIMARY KEY,
        timestamp INTEGER
    )", FILES_TABLE);
    conn.execute(&files_table_cmd, params![]).expect("Couldn't create files table.");
}

// Pruning

pub async fn prune_tokens_periodically() {
    let mut timer = tokio::time::interval(chrono::Duration::minutes(10).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async { prune_tokens().await; });
    }
}

pub async fn prune_pending_tokens_periodically() {
    let mut timer = tokio::time::interval(chrono::Duration::minutes(10).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async { prune_pending_tokens().await; });
    }
}

pub async fn prune_files_periodically() {
    let mut timer = tokio::time::interval(chrono::Duration::days(1).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async { prune_files().await; });
    }
}

async fn prune_tokens() {
    let rooms = match get_all_rooms().await {
        Ok(rooms) => rooms,
        Err(_) => return
    };
    for room in rooms {
        let pool = pool_by_room_name(&room);
        // It's not catastrophic if we fail to prune the database for a given room
        let mut conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => return println!("Couldn't prune tokens due to error: {}.", e)
        };
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => return println!("Couldn't prune tokens due to error: {}.", e)
        };
        let stmt = format!("DELETE FROM {} WHERE timestamp < (?1)", TOKENS_TABLE);
        let now = chrono::Utc::now().timestamp();
        let expiration = now - TOKEN_EXPIRATION;
        match tx.execute(&stmt, params![ expiration ]) {
            Ok(_) => (),
            Err(e) => return println!("Couldn't prune tokens due to error: {}.", e)
        };
        match tx.commit() {
            Ok(_) => (),
            Err(e) => return println!("Couldn't prune tokens due to error: {}.", e)
        };
    }
    println!("Pruned tokens.");
}

async fn prune_pending_tokens() {
    let rooms = match get_all_rooms().await {
        Ok(rooms) => rooms,
        Err(_) => return
    };
    for room in rooms {
        let pool = pool_by_room_name(&room);
        // It's not catastrophic if we fail to prune the database for a given room
        let mut conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => return println!("Couldn't prune pending tokens due to error: {}.", e)
        };
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => return println!("Couldn't prune pending tokens due to error: {}.", e)
        };
        let stmt = format!("DELETE FROM {} WHERE timestamp < (?1)", PENDING_TOKENS_TABLE);
        let now = chrono::Utc::now().timestamp();
        let expiration = now - PENDING_TOKEN_EXPIRATION;
        match tx.execute(&stmt, params![ expiration ]) {
            Ok(_) => (),
            Err(e) => return println!("Couldn't prune pending tokens due to error: {}.", e)
        };
        match tx.commit() {
            Ok(_) => (),
            Err(e) => return println!("Couldn't prune pending tokens due to error: {}.", e)
        };
    }
    println!("Pruned pending tokens.");
}

async fn prune_files() {
    let rooms = match get_all_rooms().await {
        Ok(rooms) => rooms,
        Err(_) => return
    };
    for room in rooms {
        // It's not catastrophic if we fail to prune the database for a given room
        let pool = pool_by_room_name(&room);
        let now = chrono::Utc::now().timestamp();
        let expiration = now - FILE_EXPIRATION;
        // Get a database connection and open a transaction
        let mut conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => return println!("Couldn't prune files due to error: {}.", e)
        };
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => return println!("Couldn't prune files due to error: {}.", e)
        };
        // Get the IDs of the files to delete
        let ids: Vec<String> = {
            let raw_query = format!("SELECT id FROM {} WHERE timestamp < (?1)", FILES_TABLE);
            let mut query = match tx.prepare(&raw_query) {
                Ok(query) => query,
                Err(e) => return println!("Couldn't prune files due to error: {}.", e)
            };
            let rows = match query.query_map(params![ expiration ], |row| {
                Ok(row.get(0)?)
            }) {
                Ok(rows) => rows,
                Err(e) => {
                    return println!("Couldn't prune files due to error: {}.", e);
                }
            };
            rows.filter_map(|result| result.ok()).collect()
        };
        // Delete the files
        let mut deleted_ids: Vec<String> = vec![];
        for id in ids {
            match fs::remove_file(format!("files/{}", id)) {
                Ok(_) => deleted_ids.push(id),
                Err(e) => println!("Couldn't delete file due to error: {}.", e)
            }
        }
        // Remove the file records from the database (only for the files that were actually deleted)
        let stmt = format!("DELETE FROM {} WHERE id IN (?1)", FILES_TABLE);
        match tx.execute(&stmt, params![ deleted_ids ]) {
            Ok(_) => (),
            Err(e) => return println!("Couldn't prune files due to error: {}.", e)
        };
        match tx.commit() {
            Ok(_) => (),
            Err(e) => return println!("Couldn't prune files due to error: {}.", e)
        };
    }
    println!("Pruned files.");
}

async fn get_all_rooms() -> Result<Vec<String>, Error> {
    // Get a database connection
    let conn = MAIN_POOL.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT name FROM {}", MAIN_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| {
        Ok(row.get(0)?)
    }) {
        Ok(rows) => rows,
        Err(e) => {
            println!("Couldn't query database due to error: {}.", e);
            return Err(Error::DatabaseFailedInternally);
        }
    };
    let names: Vec<String> = rows.filter_map(|result| result.ok()).collect();
    // Return
    return Ok(names);
}