use std::collections::HashMap;
use std::sync::Mutex;

use rusqlite::params;

use r2d2_sqlite::SqliteConnectionManager;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

pub const PENDING_TOKEN_EXPIRATION: i64 = 10 * 60;
pub const TOKEN_EXPIRATION: i64 = 7 * 24 * 60 * 60;

pub const MESSAGES_TABLE: &str = "messages";
pub const DELETED_MESSAGES_TABLE: &str = "deleted_messages";
pub const MODERATORS_TABLE: &str = "moderators";
pub const BLOCK_LIST_TABLE: &str = "block_list";
pub const PENDING_TOKENS_TABLE: &str = "pending_tokens";
pub const TOKENS_TABLE: &str = "tokens";

lazy_static::lazy_static! {

    static ref POOLS: Mutex<HashMap<String, DatabaseConnectionPool>> = Mutex::new(HashMap::new());
}

pub fn pool(room: &str) -> DatabaseConnectionPool {
    let mut pools = POOLS.lock().unwrap();
    if let Some(pool) = pools.get(room) {
        return pool.clone();
    } else {
        let file_name = format!("{}.db", room);
        let db_manager = r2d2_sqlite::SqliteConnectionManager::file(file_name);
        let pool = r2d2::Pool::new(db_manager).unwrap();
        pools.insert(room.to_string(), pool);
        return pools[room].clone();
    }
}

pub fn create_database_if_needed(room: &str) {
    let pool = pool(room);
    let conn = pool.get().unwrap();
    create_tables_if_needed(&conn);
}

fn create_tables_if_needed(conn: &DatabaseConnection) {
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
}

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

async fn prune_tokens() {
    let pool = pool("main");
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
    println!("Pruned tokens.");
}

async fn prune_pending_tokens() {
    let pool = pool("main");
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
    println!("Pruned pending tokens.");
}