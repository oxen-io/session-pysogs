use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use log::{error, info};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use rusqlite_migration::{Migrations, M};

use super::errors::Error;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

// Main

pub const MAIN_TABLE: &str = "main";

lazy_static::lazy_static! {

    pub static ref MAIN_POOL: DatabaseConnectionPool = {
        let file_name = "database.db";
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
        name TEXT,
        image_id TEXT
    )",
        MAIN_TABLE
    );
    conn.execute(&main_table_cmd, params![]).expect("Couldn't create main table.");
}

// Rooms

pub const PENDING_TOKEN_EXPIRATION: i64 = 10 * 60;
pub const TOKEN_EXPIRATION: i64 = 7 * 24 * 60 * 60;
pub const FILE_EXPIRATION: i64 = 15 * 24 * 60 * 60;

pub const MESSAGES_TABLE: &str = "messages";
pub const DELETED_MESSAGES_TABLE: &str = "deleted_messages";
pub const MODERATORS_TABLE: &str = "moderators";
pub const BLOCK_LIST_TABLE: &str = "block_list";
pub const PENDING_TOKENS_TABLE: &str = "pending_tokens";
pub const TOKENS_TABLE: &str = "tokens";
pub const FILES_TABLE: &str = "files";
pub const USER_ACTIVITY_TABLE: &str = "user_activity";

lazy_static::lazy_static! {

    static ref POOLS: Mutex<HashMap<String, DatabaseConnectionPool>> = Mutex::new(HashMap::new());
}

pub fn pool_by_room_id(room_id: &str) -> DatabaseConnectionPool {
    let mut pools = POOLS.lock().unwrap();
    if let Some(pool) = pools.get(room_id) {
        return pool.clone();
    } else {
        let raw_path = format!("rooms/{}.db", room_id);
        let path = Path::new(&raw_path);
        let db_manager = r2d2_sqlite::SqliteConnectionManager::file(path);
        let pool = r2d2::Pool::new(db_manager).unwrap();
        pools.insert(room_id.to_string(), pool);
        return pools[room_id].clone();
    }
}

pub fn create_database_if_needed(room_id: &str) {
    let pool = pool_by_room_id(room_id);
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
        timestamp INTEGER,
        data TEXT,
        signature TEXT,
        is_deleted INTEGER
    )",
        MESSAGES_TABLE
    );
    conn.execute(&messages_table_cmd, params![]).expect("Couldn't create messages table.");
    // Deleted messages
    let deleted_messages_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        id INTEGER PRIMARY KEY,
        deleted_message_id INTEGER
    )",
        DELETED_MESSAGES_TABLE
    );
    conn.execute(&deleted_messages_table_cmd, params![])
        .expect("Couldn't create deleted messages table.");
    // Moderators
    let moderators_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT
    )",
        MODERATORS_TABLE
    );
    conn.execute(&moderators_table_cmd, params![]).expect("Couldn't create moderators table.");
    // Block list
    let block_list_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT
    )",
        BLOCK_LIST_TABLE
    );
    conn.execute(&block_list_table_cmd, params![]).expect("Couldn't create block list table.");
    // Pending tokens
    // Note that a given public key can have multiple pending tokens
    let pending_tokens_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT,
        timestamp INTEGER,
        token BLOB
    )",
        PENDING_TOKENS_TABLE
    );
    conn.execute(&pending_tokens_table_cmd, params![])
        .expect("Couldn't create pending tokens table.");
    // Tokens
    // The token is stored as hex here (rather than as bytes) because it's more convenient for lookup
    let tokens_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT,
        timestamp INTEGER,
        token TEXT PRIMARY KEY
    )",
        TOKENS_TABLE
    );
    conn.execute(&tokens_table_cmd, params![]).expect("Couldn't create tokens table.");
    // Files
    let files_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        id TEXT PRIMARY KEY,
        timestamp INTEGER
    )",
        FILES_TABLE
    );
    conn.execute(&files_table_cmd, params![]).expect("Couldn't create files table.");
    // User activity table
    let user_activity_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT PRIMARY KEY,
        last_active INTEGER NOT NULL
    )",
        USER_ACTIVITY_TABLE,
    );
    conn.execute(&user_activity_table_cmd, params![])
        .expect("Couldn't create user activity table.");
}

// Pruning

pub async fn prune_tokens_periodically() {
    let mut timer = tokio::time::interval(chrono::Duration::minutes(10).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async {
            prune_tokens().await;
        });
    }
}

pub async fn prune_pending_tokens_periodically() {
    let mut timer = tokio::time::interval(chrono::Duration::minutes(10).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async {
            prune_pending_tokens().await;
        });
    }
}

pub async fn prune_files_periodically() {
    let mut timer = tokio::time::interval(chrono::Duration::days(1).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async {
            prune_files(FILE_EXPIRATION).await;
        });
    }
}

async fn prune_tokens() {
    let rooms = match get_all_room_ids() {
        Ok(rooms) => rooms,
        Err(_) => return,
    };
    for room in rooms {
        let pool = pool_by_room_id(&room);
        // It's not catastrophic if we fail to prune the database for a given room
        let conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => return error!("Couldn't prune tokens due to error: {}.", e),
        };
        let stmt = format!("DELETE FROM {} WHERE timestamp < (?1)", TOKENS_TABLE);
        let now = chrono::Utc::now().timestamp();
        let expiration = now - TOKEN_EXPIRATION;
        match conn.execute(&stmt, params![expiration]) {
            Ok(_) => (),
            Err(e) => return error!("Couldn't prune tokens due to error: {}.", e),
        };
    }
    info!("Pruned tokens.");
}

async fn prune_pending_tokens() {
    let rooms = match get_all_room_ids() {
        Ok(rooms) => rooms,
        Err(_) => return,
    };
    for room in rooms {
        let pool = pool_by_room_id(&room);
        // It's not catastrophic if we fail to prune the database for a given room
        let conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => return error!("Couldn't prune pending tokens due to error: {}.", e),
        };
        let stmt = format!("DELETE FROM {} WHERE timestamp < (?1)", PENDING_TOKENS_TABLE);
        let now = chrono::Utc::now().timestamp();
        let expiration = now - PENDING_TOKEN_EXPIRATION;
        match conn.execute(&stmt, params![expiration]) {
            Ok(_) => (),
            Err(e) => return error!("Couldn't prune pending tokens due to error: {}.", e),
        };
    }
    info!("Pruned pending tokens.");
}

pub async fn prune_files(file_expiration: i64) {
    // The expiration setting is passed in for testing purposes
    let rooms = match get_all_room_ids() {
        Ok(rooms) => rooms,
        Err(_) => return,
    };
    for room in rooms {
        // It's not catastrophic if we fail to prune the database for a given room
        let pool = pool_by_room_id(&room);
        let now = chrono::Utc::now().timestamp();
        let expiration = now - file_expiration;
        // Get a database connection and open a transaction
        let conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => {
                return error!(
                    "Couldn't get database connection to prune files due to error: {}.",
                    e
                )
            }
        };
        // Get the IDs of the files to delete
        let raw_query = format!("SELECT id FROM {} WHERE timestamp < (?1)", FILES_TABLE);
        let mut query = match conn.prepare(&raw_query) {
            Ok(query) => query,
            Err(e) => return error!("Couldn't prepare query to prune files due to error: {}.", e),
        };
        let rows = match query.query_map(params![expiration], |row| row.get(0)) {
            Ok(rows) => rows,
            Err(e) => {
                return error!(
                    "Couldn't prune files due to error: {} (expiration = {}).",
                    e, expiration
                );
            }
        };
        let ids: Vec<String> = rows.filter_map(|result| result.ok()).collect();
        if !ids.is_empty() {
            // Delete the files
            let mut deleted_ids: Vec<String> = vec![];
            for id in ids {
                match fs::remove_file(format!("files/{}_files/{}", room, id)) {
                    Ok(_) => deleted_ids.push(id),
                    Err(e) => {
                        error!(
                            "Couldn't delete file: {} from room: {} due to error: {}.",
                            id, room, e
                        );
                        deleted_ids.push(id);
                    }
                }
            }
            // Remove the file records from the database
            // FIXME: It'd be great to do this in a single statement, but apparently this is not supported very well
            for id in deleted_ids {
                let stmt = format!("DELETE FROM {} WHERE id = (?1)", FILES_TABLE);
                match conn.execute(&stmt, params![id]) {
                    Ok(_) => (),
                    Err(e) => {
                        return error!("Couldn't prune file with ID: {} due to error: {}.", id, e)
                    }
                };
            }
            // Log the result
            info!("Pruned files for room: {}.", room);
        }
    }
}

// Migration

pub fn perform_migration() {
    let rooms = match get_all_room_ids() {
        Ok(ids) => ids,
        Err(_e) => {
            return error!("Couldn't get all room IDs.");
        }
    };
    let create_tokens_table_cmd = format!(
        "CREATE TABLE IF NOT EXISTS {} (
        public_key TEXT,
        timestamp INTEGER,
        token TEXT PRIMARY KEY
    )",
        TOKENS_TABLE
    );
    let migrations =
        Migrations::new(vec![M::up("DROP TABLE tokens"), M::up(&create_tokens_table_cmd)]);
    for room in rooms {
        create_database_if_needed(&room);
        let pool = pool_by_room_id(&room);
        let mut conn = pool.get().unwrap();
        migrations.to_latest(&mut conn).unwrap();
    }
}

// Utilities

fn get_all_room_ids() -> Result<Vec<String>, Error> {
    // Get a database connection
    let conn = MAIN_POOL.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = format!("SELECT id FROM {}", MAIN_TABLE);
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| row.get(0)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(Error::DatabaseFailedInternally);
        }
    };
    let ids: Vec<String> = rows.filter_map(|result| result.ok()).collect();
    // Return
    return Ok(ids);
}
