use std::fs;
use std::time::{Duration, SystemTime};

use log::{error, info, warn};
use r2d2_sqlite::SqliteConnectionManager;
use regex::Regex;
use rusqlite::{config::DbConfig, params};
//use rusqlite_migration::{Migrations, M};

use super::errors::Error;
use super::models::Room;

pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;
pub type DatabaseTransaction<'a> = rusqlite::Transaction<'a>;

#[derive(PartialEq, Eq, Hash)]
pub struct RoomId {
    id: String,
}

lazy_static::lazy_static! {
    // Alphanumeric, Decimals "-" & "_" only and must be between 1 - 64 characters
    static ref REGULAR_CHARACTERS_ONLY: Regex = Regex::new(r"^[\w-]{1,64}$").unwrap();
}

impl RoomId {
    pub fn validate(room_id: &str) -> Result<(), Error> {
        return if REGULAR_CHARACTERS_ONLY.is_match(room_id) {
            Ok(())
        } else {
            Err(Error::ValidationFailed)
        }
    }

    pub fn new(room_id: &str) -> Result<RoomId, Error> {
        RoomId::validate(room_id)?;
        Ok(RoomId { id: room_id.to_string() })
    }

    pub fn get_id(&self) -> &str {
        &self.id
    }
}

// How long without activity before we drop user-room activity info.
pub const ROOM_ACTIVE_PRUNE_THRESHOLD: Duration = Duration::from_secs(60 * 86400);

// How long we keep message edit/deletion history.
pub const MESSAGE_HISTORY_PRUNE_THRESHOLD: Duration = Duration::from_secs(30 * 86400);

lazy_static::lazy_static! {

    static ref DB_POOL: DatabaseConnectionPool = {
        let file_name = "sogs.db";
        let db_manager = r2d2_sqlite::SqliteConnectionManager::file(file_name)
            .with_init(|c| {
                c.set_prepared_statement_cache_capacity(100);
                c.execute_batch("
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;
                ")?;
                if !c.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)? {
                    panic!("Unable to enable foreign key support; perhaps sqlite3 is compiled without it‽");
                }
                if !c.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)? {
                    panic!("Unable to enable trigger support; perhaps sqlite3 is built without it‽");
                }
                Ok(())
            });
        return r2d2::Pool::new(db_manager).unwrap();
    };
}

pub fn get_conn() -> Result<DatabaseConnection, Error> {
    match DB_POOL.get() {
        Ok(conn) => Ok(conn),
        Err(e) => {
            error!("Unable to get database connection: {}", e);
            return Err(Error::DatabaseFailedInternally);
        }
    }
}

pub fn get_transaction<'a>(
    conn: &'a mut DatabaseConnection
) -> Result<DatabaseTransaction<'a>, Error> {
    conn.transaction().map_err(db_error)
}

pub fn db_error(e: rusqlite::Error) -> Error {
    error!("Database query failed: {}", e);
    return Error::DatabaseFailedInternally;
}

/// Initialize the database, creating and migrating its structure if necessary.
pub fn create_database_if_needed() {
    if rusqlite::version_number() < 3035000 {
        panic!("SQLite 3.35.0+ is required!");
    }

    let conn = get_conn().unwrap();

    let have_messages = match conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
        params![],
        |row| row.get::<_, bool>(0)
    ) {
        Ok(exists) => exists,
        Err(e) => {
            panic!("Error querying database: {}", e);
        }
    };

    if !have_messages {
        conn.execute_batch(include_str!("schema.sql")).expect("Couldn't create database schema.");

        // TODO: migration code from old multi-DB structure goes here
    }

    // Future DB migration code goes here
}

// Performs periodic DB maintenance: file pruning, delayed permission applying,
// etc.
pub async fn db_maintenance_job() {
    let mut timer = tokio::time::interval(chrono::Duration::seconds(10).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async {
            let now = SystemTime::now();
            if let Ok(mut conn) = get_conn() {
                prune_files(&mut conn, &now);
                prune_message_history(&mut conn, &now);
                prune_room_activity(&mut conn, &now);
                apply_permission_updates(&mut conn, &now);
            } else {
                warn!("Couldn't get a free db connection to perform database maintenance; will retry soon");
            }
        });
    }
}

/// Removes all files with expiries <= the given time (which should generally by
/// `SystemTime::now()`, except in the test suite).
fn prune_files(conn: &mut DatabaseConnection, now: &SystemTime) {
    let mut st = match conn.prepare_cached("DELETE FROM files WHERE expiry <= ? RETURNING path") {
        Ok(st) => st,
        Err(e) => {
            error!("Unable to prepare statement: {}", e);
            return;
        }
    };
    let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();
    let mut rows = match st.query(params![now_secs]) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Unable to delete expired file rows: {}", e);
            return;
        }
    };

    let mut count = 0;
    while let Ok(Some(row)) = rows.next() {
        if let Ok(path) = row.get_ref_unwrap(0).as_str() {
            if let Err(e) = fs::remove_file(path) {
                error!("Couldn't delete expired file '{}': {}", path, e);
            } else {
                count += 1;
            }
        }
    }
    if count > 0 {
        info!("Pruned {} expired/deleted files", count);
    }
}

/// Prune old message edit/deletion history
fn prune_message_history(conn: &mut DatabaseConnection, now: &SystemTime) {
    let mut st = match conn.prepare_cached("DELETE FROM message_history WHERE replaced <= ?") {
        Ok(st) => st,
        Err(e) => {
            error!("Unable to prepare message history prune statement: {}", e);
            return;
        }
    };
    let now_secs = (*now - MESSAGE_HISTORY_PRUNE_THRESHOLD)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let count = match st.execute(params![now_secs]) {
        Ok(count) => count,
        Err(e) => {
            error!("Unable to prune message history: {}", e);
            return;
        }
    };
    if count > 0 {
        info!("Pruned {} message edits/deletions", count);
    }
}

fn prune_room_activity(conn: &mut DatabaseConnection, now: &SystemTime) {
    let mut st = match conn.prepare_cached("DELETE FROM room_users WHERE last_active <= ?") {
        Ok(st) => st,
        Err(e) => {
            error!("Unable to prepare room activity prune statement: {}", e);
            return;
        }
    };
    let now_secs = (*now - ROOM_ACTIVE_PRUNE_THRESHOLD)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let count = match st.execute(params![now_secs]) {
        Ok(count) => count,
        Err(e) => {
            error!("Unable to prune room activity: {}", e);
            return;
        }
    };
    if count > 0 {
        info!("Pruned {} old room activity records", count);
    }
}

fn apply_permission_updates(conn: &mut DatabaseConnection, now: &SystemTime) {
    let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();

    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            error!("Unable to begin transaction: {}", e);
            return;
        }
    };
    {
        let mut ins_st = match tx.prepare_cached(
            "
            INSERT INTO user_permission_overrides (room, user, read, write, upload)
                SELECT room, user, read, write, upload FROM user_permission_futures WHERE at <= ?
                ON CONFLICT DO UPDATE SET
                    read = COALESCE(excluded.read, read),
                    write = COALESCE(excluded.write, write),
                    upload = COALESCE(excluded.upload, upload)"
        ) {
            Ok(st) => st,
            Err(e) => {
                error!("Unable to prepare statement: {}", e);
                return;
            }
        };
        let mut del_st =
            match tx.prepare_cached("DELETE FROM user_permission_futures WHERE at <= ?") {
                Ok(st) => st,
                Err(e) => {
                    error!("Unable to prepare statement: {}", e);
                    return;
                }
            };
        let num_applied = match ins_st.execute(params![now_secs]) {
            Ok(num) => num,
            Err(e) => {
                error!("Unable to apply scheduled future permissions: {}", e);
                return;
            }
        };
        if num_applied > 0 {
            info!("Applied {} user permission updates", num_applied);
            if let Err(e) = del_st.execute(params![now_secs]) {
                error!("Unable to delete applied future permissions: {}", e);
                return;
            }
        }
    }

    if let Err(e) = tx.commit() {
        error!("Failed to commit scheduled user permission updates: {}", e);
        return;
    }
}

// Utilities

pub fn get_room_from_token(
    conn: &rusqlite::Connection,
    token: &str
) -> Result<Room, Error>
{
    match conn
        .prepare_cached("SELECT * FROM rooms WHERE token = ?")
        .map_err(db_error)?
        .query_row(params![&token], Room::from_row)
    {
        Ok(room) => return Ok(room),
        Err(rusqlite::Error::QueryReturnedNoRows) => return Err(Error::NoSuchRoom.into()),
        Err(_) => return Err(Error::DatabaseFailedInternally.into())
    }
}
