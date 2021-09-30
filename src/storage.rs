use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use log::{error, warn, info};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use rusqlite_migration::{Migrations, M};

use super::errors::Error;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

#[derive(PartialEq, Eq, Hash)]
pub struct RoomId {
    id: String,
}

lazy_static::lazy_static! {
    // Alphanumeric, Decimals "-" & "_" only and must be between 1 - 64 characters
    static ref REGULAR_CHARACTERS_ONLY: Regex = Regex::new(r"^[\w-]{1,64}$").unwrap();
}

impl RoomId {
    pub fn new(room_id: &str) -> Option<RoomId> {
        if REGULAR_CHARACTERS_ONLY.is_match(room_id) {
            return Some(RoomId { id: room_id.to_string() });
        } else {
            return None;
        }
    }

    pub fn get_id(&self) -> &str {
        &self.id
    }
}

// Main

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
    let main_table_cmd = "CREATE TABLE IF NOT EXISTS main (
        id TEXT PRIMARY KEY,
        name TEXT,
        image_id TEXT
    )";
    conn.execute(&main_table_cmd, params![]).expect("Couldn't create main table.");
}

// Rooms

pub const PENDING_TOKEN_EXPIRATION: i64 = 10 * 60;
pub const TOKEN_EXPIRATION: i64 = 7 * 24 * 60 * 60;
pub const FILE_EXPIRATION: i64 = 15 * 24 * 60 * 60;

lazy_static::lazy_static! {

    static ref POOLS: Mutex<HashMap<String, DatabaseConnectionPool>> = Mutex::new(HashMap::new());
}

pub fn pool_by_room_id(room_id: &RoomId) -> Result<DatabaseConnectionPool, Error> {
    let mut pools = POOLS.lock().unwrap();
    if let Some(pool) = pools.get(room_id.get_id()) {
        return Ok(pool.clone());
    } else {
        let pool = &MAIN_POOL;
        if let Ok(conn) = pool.get() {
            if let Ok(count) = conn.query_row("SELECT COUNT(*) FROM main WHERE id = ?", params![room_id.get_id()],
                |row| row.get::<_, i64>(0)) {
                if count == 0 {
                    warn!("Cannot access room database: room {} does not exist", room_id.get_id());
                    return Err(Error::NoSuchRoom);
                }
                let raw_path = format!("rooms/{}.db", room_id.get_id());
                let path = Path::new(&raw_path);
                let db_manager = r2d2_sqlite::SqliteConnectionManager::file(path);
                let pool = match r2d2::Pool::new(db_manager) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Unable to access {} database: {}", room_id.get_id(), e);
                        return Err(Error::DatabaseFailedInternally);
                    }
                };
                pools.insert(room_id.get_id().to_string(), pool);
                return Ok(pools[room_id.get_id()].clone());
            }
        }
        error!("Failed to query main database for room {} existence", room_id.get_id());
        return Err(Error::DatabaseFailedInternally);
    }
}

pub fn create_database_if_needed(room_id: &RoomId) {
    let pool = pool_by_room_id(room_id);
    let conn = pool.unwrap().get().unwrap();
    create_room_tables_if_needed(&conn);
}

pub fn create_room_tables_if_needed(conn: &DatabaseConnection) {
    // Messages
    // The `id` field is needed to make `rowid` stable, which is important because otherwise
    // the `id`s in this table won't correspond to those in the deleted messages table
    let messages_table_cmd = "CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        public_key TEXT,
        timestamp INTEGER,
        data TEXT,
        signature TEXT,
        is_deleted INTEGER
    )";
    conn.execute(&messages_table_cmd, params![]).expect("Couldn't create messages table.");
    // Deleted messages
    let deleted_messages_table_cmd = "CREATE TABLE IF NOT EXISTS deleted_messages (
        id INTEGER PRIMARY KEY,
        deleted_message_id INTEGER
    )";
    conn.execute(&deleted_messages_table_cmd, params![])
        .expect("Couldn't create deleted messages table.");
    // Moderators
    let moderators_table_cmd = "CREATE TABLE IF NOT EXISTS moderators (
        public_key TEXT
    )";
    conn.execute(&moderators_table_cmd, params![]).expect("Couldn't create moderators table.");
    // Block list
    let block_list_table_cmd = "CREATE TABLE IF NOT EXISTS block_list (
        public_key TEXT
    )";
    conn.execute(&block_list_table_cmd, params![]).expect("Couldn't create block list table.");
    // Pending tokens
    // Note that a given public key can have multiple pending tokens
    let pending_tokens_table_cmd = "CREATE TABLE IF NOT EXISTS pending_tokens (
        public_key TEXT,
        timestamp INTEGER,
        token BLOB
    )";
    conn.execute(&pending_tokens_table_cmd, params![])
        .expect("Couldn't create pending tokens table.");
    // Tokens
    // The token is stored as hex here (rather than as bytes) because it's more convenient for lookup
    let tokens_table_cmd = "CREATE TABLE IF NOT EXISTS tokens (
        public_key TEXT,
        timestamp INTEGER,
        token TEXT PRIMARY KEY
    )";
    conn.execute(&tokens_table_cmd, params![]).expect("Couldn't create tokens table.");
    // Files
    let files_table_cmd = "CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        timestamp INTEGER
    )";
    conn.execute(&files_table_cmd, params![]).expect("Couldn't create files table.");
    // User activity table
    let user_activity_table_cmd = "CREATE TABLE IF NOT EXISTS user_activity (
        public_key TEXT PRIMARY KEY,
        last_active INTEGER NOT NULL
    )";
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
        let pool = match pool_by_room_id(&room) {
            Ok(p) => p,
            Err(_) => return
        };
        // It's not catastrophic if we fail to prune the database for a given room
        let conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => return error!("Couldn't prune tokens due to error: {}.", e),
        };
        let stmt = "DELETE FROM tokens WHERE timestamp < (?1)";
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
        let pool = match pool_by_room_id(&room) {
            Ok(p) => p,
            Err(_) => return
        };
        // It's not catastrophic if we fail to prune the database for a given room
        let conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => return error!("Couldn't prune pending tokens due to error: {}.", e),
        };
        let stmt = "DELETE FROM pending_tokens WHERE timestamp < (?1)";
        let now = chrono::Utc::now().timestamp();
        let expiration = now - PENDING_TOKEN_EXPIRATION;
        match conn.execute(&stmt, params![expiration]) {
            Ok(_) => (),
            Err(e) => return error!("Couldn't prune pending tokens due to error: {}.", e),
        };
    }
    info!("Pruned pending tokens.");
}

fn get_expired_file_ids(
    pool: &DatabaseConnectionPool, file_expiration: i64,
) -> Result<Vec<String>, ()> {
    let now = chrono::Utc::now().timestamp();
    let expiration = now - file_expiration;
    // Get a database connection and open a transaction
    let conn = pool.get().map_err(|e| {
        error!("Couldn't get database connection to prune files due to error: {}.", e);
    })?;
    // Get the IDs of the files to delete
    let raw_query = "SELECT id FROM files WHERE timestamp < (?1)";

    let mut query = conn.prepare(&raw_query).map_err(|e| {
        error!("Couldn't prepare query to prune files due to error: {}.", e);
    })?;

    let rows = query.query_map(params![expiration], |row| row.get(0)).map_err(|e| {
        error!("Couldn't prune files due to error: {} (expiration = {}).", e, expiration);
    })?;

    Ok(rows.filter_map(|result| result.ok()).collect())
}

pub async fn prune_files_for_room(
    pool: &DatabaseConnectionPool, room: &RoomId, file_expiration: i64,
) {
    let ids = get_expired_file_ids(&pool, file_expiration);

    match ids {
        Ok(ids) if !ids.is_empty() => {
            // Delete the files
            let futs = ids.iter().map(|id| async move {
                (
                    tokio::fs::remove_file(format!("files/{}_files/{}", room.get_id(), id)).await,
                    id.to_owned(),
                )
            });

            let results = futures::future::join_all(futs).await;

            for (res, id) in results {
                if let Err(err) = res {
                    error!(
                        "Couldn't delete file: {} from room: {} due to error: {}.",
                        id,
                        room.get_id(),
                        err
                    );
                }
            }

            let conn = match pool.get() {
                Ok(conn) => conn,
                Err(e) => {
                    return error!(
                        "Couldn't get database connection to prune files due to error: {}.",
                        e
                    )
                }
            };

            // Measure the time it takes to delete all files sequentially
            // (this might become a problem since we're not using an async interface)
            let now = std::time::Instant::now();

            // Remove the file records from the database
            // FIXME: It'd be great to do this in a single statement, but apparently this is not supported very well
            for id in ids {
                let stmt = "DELETE FROM files WHERE id = (?1)";
                match conn.execute(&stmt, params![id]) {
                    Ok(_) => (),
                    Err(e) => {
                        return error!("Couldn't prune file with ID: {} due to error: {}.", id, e)
                    }
                };
            }
            // Log the result
            info!("Pruned files for room: {}. Took: {:?}", room.get_id(), now.elapsed());
        }
        Ok(_) => {
            // empty
        }
        Err(_) => {
            // It's not catastrophic if we fail to prune the database for a given room
        }
    }
}

pub async fn prune_files(file_expiration: i64) {
    // The expiration setting is passed in for testing purposes
    let rooms = match get_all_room_ids() {
        Ok(rooms) => rooms,
        Err(_) => return,
    };

    let futs = rooms.into_iter().map(|room| async move {
        if let Ok(pool) = pool_by_room_id(&room) {
            prune_files_for_room(&pool, &room, file_expiration).await;
        }
    });

    futures::future::join_all(futs).await;
}

// Migration

pub fn perform_migration() {
    let rooms = match get_all_room_ids() {
        Ok(ids) => ids,
        Err(_e) => {
            return error!("Couldn't get all room IDs.");
        }
    };
    let create_tokens_table_cmd = "CREATE TABLE IF NOT EXISTS tokens (
        public_key TEXT,
        timestamp INTEGER,
        token TEXT PRIMARY KEY
    )";
    let migrations =
        Migrations::new(vec![M::up("DROP TABLE tokens"), M::up(&create_tokens_table_cmd)]);
    for room in rooms {
        create_database_if_needed(&room);
        let pool = pool_by_room_id(&room);
        let mut conn = pool.unwrap().get().unwrap();
        migrations.to_latest(&mut conn).unwrap();
    }
}

// Utilities

fn get_all_room_ids() -> Result<Vec<RoomId>, Error> {
    // Get a database connection
    let conn = MAIN_POOL.get().map_err(|_| Error::DatabaseFailedInternally)?;
    // Query the database
    let raw_query = "SELECT id FROM main";
    let mut query = conn.prepare(&raw_query).map_err(|_| Error::DatabaseFailedInternally)?;
    let rows = match query.query_map(params![], |row| row.get(0)) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database due to error: {}.", e);
            return Err(Error::DatabaseFailedInternally);
        }
    };
    let room_ids: Vec<_> = rows
        .filter_map(|result: Result<String, _>| result.ok())
        .map(|opt| RoomId::new(&opt))
        .flatten()
        .collect();
    // Return
    return Ok(room_ids);
}
