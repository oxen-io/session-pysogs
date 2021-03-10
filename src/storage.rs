use rusqlite::{params};
use r2d2_sqlite::SqliteConnectionManager;
use warp::Rejection;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

#[derive(Debug)]
pub struct DatabaseError;
impl warp::reject::Reject for DatabaseError { }

pub fn create_tables_if_needed(conn: &DatabaseConnection) {
    // Messages
    // The `id` field is needed to make `rowid` stable
    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            text TEXT
        )",
        params![]
    ).expect("Couldn't create messages table.");
    // Deletions
    conn.execute(
        "CREATE TABLE IF NOT EXISTS deletions (
            id INTEGER PRIMARY KEY
        )",
        params![]
    ).expect("Couldn't create deletions table.");
}

// Utilities

pub fn pool() -> DatabaseConnectionPool {
    let db_manager = SqliteConnectionManager::file("database.db");
    return r2d2::Pool::new(db_manager).unwrap(); // Force
}

pub fn conn(pool: &DatabaseConnectionPool) -> Result<DatabaseConnection, Rejection> {
    match pool.get() {
        Ok(conn) => return Ok(conn),
        Err(e) => { 
            println!("Couldn't get database connection from pool due to error: {:?}.", e);
            return Err(warp::reject::custom(DatabaseError));
        }
    }
}

pub fn tx(conn: &mut DatabaseConnection) -> Result<rusqlite::Transaction, Rejection> {
    match conn.transaction() {
        Ok(tx) => return Ok(tx),
        Err(e) => { 
            println!("Couldn't open database transaction due to error: {:?}.", e);
            return Err(warp::reject::custom(DatabaseError));
        }
    }
}

/// Returns the number of rows that changed as a result of executing the given `stmt`.
pub fn exec(stmt: &str, params: &[&dyn rusqlite::ToSql], tx: &rusqlite::Transaction) -> Result<usize, Rejection> {
    match tx.execute(stmt, params) {
        Ok(count) => return Ok(count),
        Err(e) => {
            println!("Couldn't execute SQL statement due to error: {:?}.", e);
            return Err(warp::reject::custom(DatabaseError)); 
        }
    }
}