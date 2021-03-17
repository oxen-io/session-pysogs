use rusqlite::params;

use r2d2_sqlite::SqliteConnectionManager;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

pub const PENDING_TOKEN_EXPIRATION: i64 = 10 * 60;

pub const MESSAGES_TABLE: &str = "messages";
pub const DELETED_MESSAGES_TABLE: &str = "deleted_messages";
pub const MODERATORS_TABLE: &str = "moderators";
pub const BLOCK_LIST_TABLE: &str = "block_list";
pub const PENDING_TOKENS_TABLE: &str = "pending_tokens";
pub const TOKENS_TABLE: &str = "tokens";

pub fn create_tables_if_needed(conn: &DatabaseConnection) {
    // Messages
    // The `id` field is needed to make `rowid` stable, which is important because otherwise
    // the `id`s in this table won't correspond to those in the deleted messages table
    let messages_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        id INTEGER PRIMARY KEY,
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
    // A given public key can have multiple pending tokens
    let pending_tokens_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        public_key STRING,
        timestamp INTEGER,
        token BLOB
    )", PENDING_TOKENS_TABLE);
    conn.execute(&pending_tokens_table_cmd, params![]).expect("Couldn't create pending tokens table.");
    // Tokens
    let tokens_table_cmd = format!(
    "CREATE TABLE IF NOT EXISTS {} (
        public_key STRING PRIMARY KEY,
        token BLOB
    )", TOKENS_TABLE);
    conn.execute(&tokens_table_cmd, params![]).expect("Couldn't create tokens table.");
}

pub async fn prune_pending_tokens_periodically(pool: DatabaseConnectionPool) {
    let mut timer = tokio::time::interval(chrono::Duration::minutes(10).to_std().unwrap());
    loop {
        let pool = pool.clone();
        timer.tick().await;
        tokio::spawn(async { prune_pending_tokens(pool).await; });
    }
}

async fn prune_pending_tokens(pool: DatabaseConnectionPool) {
    // It's not catastrophic if we fail to prune the database
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
}