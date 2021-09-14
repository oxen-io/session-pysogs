use std::fs;
use std::time::SystemTime;

use log::{error, warn, info};
use r2d2_sqlite::SqliteConnectionManager;
use regex::Regex;
use rusqlite::params;
//use rusqlite_migration::{Migrations, M};

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

// Main

lazy_static::lazy_static! {

    pub static ref DB_POOL: DatabaseConnectionPool = {
        let file_name = "sogs.db";
        let db_manager = r2d2_sqlite::SqliteConnectionManager::file(file_name);
        // FIXME: enable wal, normal journal mode
        return r2d2::Pool::new(db_manager).unwrap();
    };
}

/// Initialize the database, creating and migrating its structure if necessary.
pub fn create_database_if_needed() {

    if rusqlite::version_number() < 3035000 {
        panic!("SQLite 3.35.0+ is required!");
    }

    let conn = DB_POOL.get().unwrap();

    let have_messages = match conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
        params![],
        |row| row.get::<_, bool>(0)) {
        Ok(exists) => exists,
        Err(e) => { panic!("Error querying database: {}", e); }
    };

    if !have_messages {
        conn.execute_batch(include_str!("create-schema.sql")).expect("Couldn't create database schema.");

        // TODO: migration code from old multi-DB structure goes here
    }

    // Future DB migration code goes here
}

// Performs periodic DB maintenance: file pruning, delayed permission applying, etc.
pub async fn db_maintenance_job() {
    let mut timer = tokio::time::interval(chrono::Duration::seconds(10).to_std().unwrap());
    loop {
        timer.tick().await;
        tokio::spawn(async {
            let now = SystemTime::now();
            if let Ok(mut conn) = DB_POOL.get() {
                prune_files(&mut conn, now);
                apply_permission_updates(&mut conn, now);
            } else {
                warn!("Couldn't get a free db connection to perform database maintenance; will retry soon");
            }
        });
    }
}

/// Removes all files with expiries <= the given time (which should generally by
/// `SystemTime::now()`, except in the test suite).
pub fn prune_files(conn: &mut DatabaseConnection, now: SystemTime) {

    let mut st = match conn.prepare_cached("DELETE FROM files WHERE expiry <= ? RETURNING path") {
        Ok(st) => st,
        Err(e) => { error!("Unable to prepare statement: {}", e); return; }
    };
    let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();
    let mut rows = match st.query(params![now_secs]) {
        Ok(rows) => rows,
        Err(e) => { error!("Unable to query expired files: {}", e); return; }
    };

    let mut count = 0;
    while let Ok(Some(row)) = rows.next() {
        if let Ok(path) = row.get_ref_unwrap(1).as_str() {
            let p = format!("files/{}", path);
            if let Err(e) = fs::remove_file(p) {
                error!("Couldn't delete expired file 'files/{}': {}", path, e);
            } else {
                count += 1;
            }
        }
    }
    info!("Pruned {} files", count);
}

pub fn apply_permission_updates(conn: &mut DatabaseConnection, now: SystemTime) {
    let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();

    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(e) => { error!("Unable to begin transaction: {}", e); return; }
    };
    {
        let mut ins_st = match tx.prepare_cached("
            INSERT INTO user_permission_overrides (room, user, read, write, upload)
                SELECT room, user, read, write, upload FROM user_permissions_future WHERE at <= ?
                ON CONFLICT DO UPDATE SET
                    read = COALESCE(excluded.read, read),
                    write = COALESCE(excluded.write, write),
                    upload = COALESCE(excluded.upload, upload)") {
            Ok(st) => st,
            Err(e) => { error!("Unable to prepare statement: {}", e); return; }
        };
        let mut del_st = match tx.prepare_cached("DELETE FROM user_permissions_future WHERE at <= ?") {
            Ok(st) => st,
            Err(e) => { error!("Unable to prepare statement: {}", e); return; }
        };
        let num_applied = match ins_st.execute(params![now_secs]) {
            Ok(num) => num,
            Err(e) => { error!("Unable to apply scheduled future permissions: {}", e); return; }
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
