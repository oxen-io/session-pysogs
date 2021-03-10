use rusqlite::{params};
use r2d2_sqlite::SqliteConnectionManager;
use warp::Rejection;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

#[derive(Debug)]
pub struct DatabaseError;
impl warp::reject::Reject for DatabaseError { }

pub fn get_db_pool() -> DatabaseConnectionPool {
    let db_manager = SqliteConnectionManager::file("database.db");
    return r2d2::Pool::new(db_manager).unwrap(); // Force
}

pub fn get_db_conn(db_pool: &DatabaseConnectionPool) -> Result<DatabaseConnection, Rejection> {
    match db_pool.get() {
        Ok(db_conn) => return Ok(db_conn),
        Err(e) => { 
            println!("Couldn't get database connection from pool due to error: {:?}.", e);
            return Err(warp::reject::custom(DatabaseError));
        }
    }
}

pub fn get_tx(db_conn: &mut DatabaseConnection) -> Result<rusqlite::Transaction, Rejection> {
    match db_conn.transaction() {
        Ok(tx) => return Ok(tx),
        Err(e) => { 
            println!("Couldn't open database transaction due to error: {:?}.", e);
            return Err(warp::reject::custom(DatabaseError));
        }
    }
}

pub fn create_tables_if_needed(db_conn: &DatabaseConnection) {
    // Messages
    // The `id` field is needed to make `rowid` stable
    db_conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            text TEXT
        )",
        params![]
    ).expect("Couldn't create messages table.");
    // Deletions
    db_conn.execute(
        "CREATE TABLE IF NOT EXISTS deletions (
            id INTEGER PRIMARY KEY
        )",
        params![]
    ).expect("Couldn't create deletions table.");
}

pub fn execute(statement: &str, params: &[&dyn rusqlite::ToSql], db_conn: &DatabaseConnection) -> Result<usize, Rejection> {
    match db_conn.execute(statement, params) {
        Ok(changed_row_count) => return Ok(changed_row_count),
        Err(e) => {
            println!("Couldn't execute SQL statement due to error: {:?}.", e);
            return Err(warp::reject::custom(DatabaseError)); 
        }
    }
}