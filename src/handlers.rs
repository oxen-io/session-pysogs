use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

use base64;
use ed25519_dalek::Signer;
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use regex::Regex;
use rusqlite::{params, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

use super::crypto;
use super::errors::Error;
use super::models;
use super::models::{OldMessage, Room, User};
use super::rpc;
use super::storage::{self, db_error};

// TODO FIXME: the user/room arguments are rather random in here.  Should rearrange them all so
// that room-dependent functions have args (room, user, ...)

// Type for requiring permissions for various endpoints.  Note that `moderator` is satisfied by
// someone being an admin in the database, and read/write/upload are always considered satisfied
// for moderators/admins.
#[derive(Default)]
pub struct AuthorizationRequired {
    pub admin: bool,     // Required admin permission (server or room)
    pub moderator: bool, // Requires moderator or admin permission (server or room)
    pub read: bool,      // Requires read permission
    pub write: bool,     // Requires write permission
    pub upload: bool,    // Requires upload permission
}

#[derive(Debug, Serialize)]
pub struct GenericStringResponse {
    pub status_code: u16,
    pub result: String,
}

// FIXME: this is used to query the github API periodically to find new releases.  Ew.
pub const SESSION_VERSION_UPDATE_INTERVAL: i64 = 30 * 60;

// Default duration for getting an active user count in a room.  Should be <=
// storage::ROOM_ACTIVE_PRUNE_THRESHOLD.
pub const ROOM_DEFAULT_ACTIVE_THRESHOLD: Duration = Duration::from_secs(7 * 86400);

// Rate limit posting if the user has posted N or more messages in the last M seconds.  This is a
// very crude way of rate limiting, but it should be sufficient for now.
//
// TODO: allow individual rooms to have more restricted rate limiting.
pub const RATE_LIMIT_POSTS: i64 = 5;
pub const RATE_LIMIT_INTERVAL: i64 = 16;

lazy_static::lazy_static! {

    pub static ref SESSION_VERSIONS: RwLock<HashMap<String, (i64, String)>> = RwLock::new(HashMap::new());

    // We strip out anything that matches here in an uploaded filename and replace with an _.
    pub static ref UPLOAD_FILENAME_BAD: Regex = Regex::new(r"[^\w+\-.'()@\[\]]+").unwrap();
}

// We truncate filenames if the sanitized name (not including the initial 'ID_') is longer than
// this.
pub const UPLOAD_FILENAME_MAX: usize = 60;
// When a filename exceeds _MAX, we keep this much from the beginning, append ..., and then append
// enough from the end (i.e. max - this - 3) to hit the _MAX value.
pub const UPLOAD_FILENAME_KEEP_PREFIX: usize = 40;
pub const UPLOAD_FILENAME_KEEP_SUFFIX: usize = 17;

// How long until an upload expires.
//
// TODO FIXME -- this could easily be a per-room property. Note that room image uploads do not
// expire (until they are replaced).
pub const UPLOAD_DEFAULT_EXPIRY: Duration = Duration::from_secs(15 * 86400);

// Backwards compatibility token sizes.  We return a "token" consisting of [SESSIONID][SIGNATURE]
// where SESSIONID is the provided session id (in bytes) and SIGNATURE is the session ID signed by
// the server's crypto::TOKEN_SIGNING_KEY.  (This all gets encrypted and sent back to the server,
// where we parse and verify the signature).
pub const TOKEN_ID_SIZE: usize = 33;
pub const TOKEN_SIG_SIZE: usize = 64;
pub const TOKEN_SIZE: usize = TOKEN_ID_SIZE + TOKEN_SIG_SIZE;

// Rooms
//
#[derive(Deserialize)]
pub struct CreateRoom {
    pub token: String,
    pub name: String,
}

// Not publicly exposed.

pub async fn create_room(room: CreateRoom) -> Result<Response, Rejection> {
    storage::RoomId::validate(&room.token)?;

    // Get a connection
    let conn = storage::get_conn()?;
    if let Err(e) = create_room_with_conn(&conn, &room) {
        error!("Couldn't create room: {}.", e);
        return Err(warp::reject::custom(Error::DatabaseFailedInternally));
    }

    // Return
    info!("Added room with ID: {}", room.token);
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    Ok(warp::reply::json(&json).into_response())
}

pub fn create_room_with_conn(
    conn: &PooledConnection<SqliteConnectionManager>,
    room: &CreateRoom,
) -> Result<usize, rusqlite::Error> {
    // Insert the room
    let stmt = "INSERT INTO rooms (token, name) VALUES (?, ?) \
                ON CONFLICT DO UPDATE SET token = excluded.token, name = excluded.name";
    return conn.execute(&stmt, params![room.token, room.name]);
}

// Not publicly exposed.
pub async fn delete_room(token: String) -> Result<Response, Rejection> {
    // Get a connection
    let conn = storage::get_conn()?;
    // Insert the room
    let stmt = "DELETE FROM rooms WHERE token = ?";
    let count = match conn.execute(&stmt, params![&token]) {
        Ok(c) => c,
        Err(e) => {
            error!("Couldn't delete room: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let status_code = if count > 0 {
        info!("Deleted room with ID: {}", &token);
        StatusCode::OK
    } else {
        warn!("Room with ID {} not found", &token);
        StatusCode::NOT_FOUND
    }
    .as_u16();
    let json = models::StatusCode { status_code };
    Ok(warp::reply::json(&json).into_response())
}

// TODO FIXME -- this endpoint is entirely unauthenticated, which doesn't seem desirable because it
// means we can't enforce bans at the global or room level.  This is undesirable: we should require
// an authenticated request for *every* endpoint.  (Also: get_room, get_room_image).
//
// The authentication level here could simply be that it requires nothing (which will become simply
// !banned).

// Deprecated: returns just "id" (actually token) and name, as older Session clients expect.
pub fn get_room_v01x(room: &Room) -> Result<Response, Rejection> {
    let response = json!({
        "status_code": StatusCode::OK.as_u16(),
        "room": {
            "id": room.token,
            "name": room.name
        }
    });
    Ok(warp::reply::json(&response).into_response())
}

// TODO FIXME -- this endpoint is entirely unauthenticated, which doesn't seem desirable because it
// means we can't enforce bans at the global or room level.  This is undesirable: we should require
// an authenticated request for *every* endpoint.  (Also: get_room, get_room_image).

fn get_all_rooms_impl() -> Result<Vec<Room>, Rejection> {
    match storage::get_conn()?
        .prepare_cached("SELECT * from rooms ORDER BY token")
        .map_err(db_error)?
        .query_map(params![], Room::from_row)
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get rooms: {}.", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    }
    .collect::<Result<Vec<Room>, _>>()
    .map_err(|e| db_error(e).into())
}

// Deprecated: returns just "id" (actually the token) and name for each room, as older Session
// clients expect.
pub fn get_all_rooms_v01x() -> Result<Response, Rejection> {
    #[derive(Debug, Serialize)]
    struct OldRoom {
        id: String,
        name: String,
    }

    let rooms = get_all_rooms_impl()?
        .into_iter()
        .map(|r| OldRoom { id: r.token, name: r.name })
        .collect::<Vec<OldRoom>>();

    let response = json!({ "status_code": StatusCode::OK.as_u16(), "rooms": rooms });
    Ok(warp::reply::json(&response).into_response())
}

// Files

/// RAII class holding an in-progress upload transaction and path details.  If this is dropped
/// without `commit()` being called we remove the file from disk and abort the transaction
/// inserting the upload into the database.
pub struct FileUpload<'a> {
    pub id: i64,        // The value of `id` in the `files` table for this new file
    pub room: &'a Room, // The room the file is uploaded to
    pub path: String,   // The relative path containing the in-progress file upload
    tx: Option<rusqlite::Transaction<'a>>,
    committed: bool,
}
impl FileUpload<'_> {
    pub fn new<'a>(tx: rusqlite::Transaction<'a>, room: &'a Room) -> FileUpload<'a> {
        FileUpload { id: -1, room, path: "".to_string(), tx: Some(tx), committed: false }
    }
    // Commits the transaction; if this succeeds the file won't be deleted on destruction
    pub fn commit(&mut self) -> Result<(), rusqlite::Error> {
        if let Some(tx) = self.tx.take() {
            tx.commit()?;
            self.committed = true;
        }
        Ok(())
    }
    pub fn prepare_cached(&self, query: &str) -> rusqlite::Result<rusqlite::CachedStatement<'_>> {
        self.tx.as_ref().unwrap().prepare_cached(query)
    }
}
impl Drop for FileUpload<'_> {
    fn drop(&mut self) {
        if !self.committed && !self.path.is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Does the actual work involved in storing a file, inserting into the database, etc.
///
/// Returns a FileUpload on success.  The caller may optionally use this to perform additional
/// actions, but *must* call `.commit()` on success -- if dropped the FileUpload will clean up the
/// temporary file and drop the transaction inserting the records.
pub fn store_file_impl<'a>(
    conn: &'a mut storage::DatabaseConnection,
    room: &'a Room,
    user: &User,
    auth: AuthorizationRequired,
    data_b64: &str,
    filename: Option<&str>,
    expires: bool,
) -> Result<FileUpload<'a>, Rejection> {
    // Determine the file size from the base64 data without decoding it (we'll do that later
    // directly to the destination file).
    let mut bytes: usize = data_b64.len() / 4 * 3;
    match data_b64.len() % 4 {
        0 => {
            // Even multiple of 4, but we might have padding:
            if data_b64.ends_with('=') {
                // Every 3 bytes of data becomes 4 bytes in base64.  If the end is a 4 byte value
                // with padding then two padding chars means it was created from a single byte (and
                // we're using 6+2 bits in the first two significant chars), and one padding char
                // means it was created from two bytes (using 6+6+4 bytes of encoded significance).
                bytes -= if data_b64.ends_with("==") { 2 } else { 1 };
            }
        }
        // Input of size 3n+{1,2} will produce 4n+{2,3} (unpadded) bytes:
        2 => {
            bytes += 1;
        }
        3 => {
            bytes += 2;
        }
        // This is just invalid base64, so bail now:
        _ => {
            error!("Invalid file data: data is not properly base64 encoded");
            return Err(Error::ValidationFailed.into());
        }
    };

    let files_dir = format!("uploads/{}", room.token);
    if let Err(e) = std::fs::create_dir_all(&files_dir) {
        error!("Unable to mkdir {} for room file storage: {}", files_dir, e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    let mut upload = FileUpload::new(storage::get_transaction(conn)?, &room);

    require_authorization(&upload.tx.as_ref().unwrap(), &user, &room, auth)?;

    let db_filename: Option<String> =
        filename.map(|f| UPLOAD_FILENAME_BAD.replace_all(f, "_").into());
    let expiry: Option<f64> = if expires {
        Some(
            (SystemTime::now() + UPLOAD_DEFAULT_EXPIRY)
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        )
    } else {
        None
    };
    upload.id = match upload
        .tx
        .as_ref()
        .unwrap()
        .prepare_cached(
            "INSERT INTO files (room, uploader, size, expiry, filename, path) \
             VALUES (?, ?, ?, ?, ?, 'tmp') \
             RETURNING id",
        )
        .map_err(db_error)?
        .query_row(params![room.id, user.id, bytes, expiry, db_filename], |row| row.get(0))
    {
        Ok(r) => r,
        Err(e) => {
            error!("Couldn't insert file row: {}.", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    };

    let mut fs_filename: String = db_filename.unwrap_or("(unnamed)".to_string());

    assert!(UPLOAD_FILENAME_KEEP_PREFIX + 3 + UPLOAD_FILENAME_KEEP_SUFFIX <= UPLOAD_FILENAME_MAX);
    if fs_filename.len() > UPLOAD_FILENAME_MAX {
        fs_filename.replace_range(
            UPLOAD_FILENAME_KEEP_PREFIX..fs_filename.len() - UPLOAD_FILENAME_KEEP_SUFFIX,
            "...",
        );
    }
    fs_filename = format!("{}/{}_{}", files_dir, upload.id, fs_filename);
    if let Err(e) = upload
        .prepare_cached("UPDATE files SET path = ? WHERE id = ?")
        .map_err(db_error)?
        .execute(params![fs_filename, upload.id])
    {
        error!("Unable to update stored path to '{}': {}", fs_filename, e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    // Write to file
    let path = Path::new(&fs_filename);
    // TODO: this could possibly be done async, but that seems dangerous while we hold an open
    // transaction here that could cause other threads to block (and thus deadlock).
    let mut file = match std::fs::File::create(path) {
        Ok(file) => file,
        Err(e) => {
            error!("Couldn't open file '{}': {}.", fs_filename, e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    };
    upload.path = fs_filename;

    // Decode 65535 of output data at a time (we can't do 65536 because we need to read off the
    // base64 in groups of 4 chars = groups of 3 bytes, and no power of 2 is divisible by 3).
    let mut buf = Vec::<u8>::new();
    let mut pos: usize = 0;
    while pos < data_b64.len() {
        let end = (pos + 87380).min(data_b64.len());
        if let Err(e) =
            base64::decode_config_buf(&data_b64.as_bytes()[pos..end], base64::STANDARD, &mut buf)
        {
            warn!("Invalid upload data: base64 decoding failed: {}", e);
            return Err(Error::ValidationFailed.into());
        }
        if let Err(e) = file.write_all(&buf) {
            error!("Writing to file {} failed: {}", upload.path, e);
            return Err(Error::DatabaseFailedInternally.into());
        }
        pos = end;
        buf.clear();
    }

    Ok(upload)
}

pub fn store_file(
    room: &Room,
    user: &User,
    data_b64: &str,
    filename: Option<&str>,
) -> Result<Response, Rejection> {
    let mut conn = storage::get_conn()?;
    if !matches!(rpc::MODE, rpc::Mode::OpenGroupServer) {
        // FIXME TODO
        todo!("FIXME file mode FIXME FIXME TODO!");
    }

    let auth = AuthorizationRequired { upload: true, write: true, ..Default::default() };

    let mut upload = match store_file_impl(&mut conn, &room, &user, auth, data_b64, filename, true)
    {
        Ok(id) => id,
        Err(e) => return Err(e),
    };

    if let Err(e) = upload.commit() {
        error!("File upload failed: {}", e);
        return Err(Error::DatabaseFailedInternally.into());
    }
    let response = json!({ "status_code": StatusCode::OK.as_u16(), "result": upload.id });
    Ok(warp::reply::json(&response).into_response())
}

// Takes a .query_row response returning the `path` field from a files row and builds it into a
// file response.
fn file_response(path_row: rusqlite::Result<String>) -> Result<Response, Rejection> {
    let raw_path = match path_row {
        Ok(path) => path,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            let response = json!({"status_code": StatusCode::NOT_FOUND.as_u16()});
            return Ok(warp::reply::json(&response).into_response());
        }
        Err(e) => {
            error!("Failed to query path from files table: {}", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    };

    // Try to read the file
    let path = Path::new(&raw_path);
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            error!("Couldn't read file: {}.", e);
            return Err(Error::ValidationFailed.into());
        }
    };

    let mut bytes = vec![];
    if let Err(e) = file.read_to_end(&mut bytes) {
        error!("Couldn't read file: {}.", e);
        return Err(Error::DatabaseFailedInternally.into());
    }
    // Base64 encode the result
    let base64_encoded_bytes = base64::encode(bytes);
    // Return
    let json = GenericStringResponse {
        status_code: StatusCode::OK.as_u16(),
        result: base64_encoded_bytes,
    };
    Ok(warp::reply::json(&json).into_response())
}

pub fn get_file(room: Room, id: i64, user: User) -> Result<Response, Rejection> {
    let conn = storage::get_conn()?;
    return get_file_conn(&conn, &room, id, user);
}

pub fn get_file_conn(
    conn: &PooledConnection<SqliteConnectionManager>,
    room: &Room,
    id: i64,
    user: User,
) -> Result<Response, Rejection> {
    require_authorization(
        &conn,
        &user,
        &room,
        AuthorizationRequired { read: true, ..Default::default() },
    )?;

    let mut row = conn
        .prepare_cached("SELECT path FROM files WHERE room = ? AND id = ?")
        .map_err(db_error)?
        .query_row(params![room.id, id], |row| row.get(0));
    if row == Err(rusqlite::Error::QueryReturnedNoRows) && *storage::HAVE_FILE_ID_HACKS {
        // Migration handling: we may have some file ID mappings from old IDs to new IDs in the
        // file_id_hacks table, so try again using it
        row = conn.prepare_cached("SELECT path FROM files WHERE id = \
                                  (SELECT file FROM file_id_hacks WHERE room = ? AND old_file_id = ?)")
            .map_err(db_error)?
            .query_row(params![room.id, id], |row| row.get(0));
    }

    file_response(row)
}

// FIXME TODO This endpoint is currently not authenticated, which seems wrong.  See comment above
// get_room()/get_all_rooms().

pub async fn get_room_image(room: Room) -> Result<Response, Rejection> {
    let conn = storage::get_conn()?;

    let row = conn
        .prepare_cached(
            "SELECT path FROM rooms JOIN files ON rooms.image = files.id WHERE rooms.id = ?",
        )
        .map_err(db_error)?
        .query_row(params![room.id], |row| row.get(0));
    file_response(row)
}

pub async fn set_room_image(
    room: Room,
    user: User,
    data_b64: &str,
    filename: Option<&str>,
) -> Result<Response, Rejection> {
    let auth = AuthorizationRequired { moderator: true, ..Default::default() };

    let mut conn = storage::get_conn()?;
    let mut upload = store_file_impl(&mut conn, &room, &user, auth, data_b64, filename, false)?;

    upload
        .prepare_cached("UPDATE rooms SET image = ? WHERE id = ?")
        .map_err(db_error)?
        .execute(params![upload.id, room.id])
        .map_err(db_error)?;

    if let Err(e) = upload.commit() {
        error!("File upload failed: {}", e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    let response = json!({ "status_code": StatusCode::OK.as_u16(), "result": upload.id });
    Ok(warp::reply::json(&response).into_response())
}

// Authentication

/// Attempts to decode a received parameter of a fixed size; the parameter can be passed as either
/// hex or base64 (the latter with or without padding).  Returns Error::InvalidRpcCall if neither
/// hex nor base64.
pub fn decode_hex_or_b64(value: &str, byte_size: usize) -> Result<Vec<u8>, Error> {
    if value.len() == byte_size * 2 {
        return hex::decode(value).map_err(|_| Error::InvalidRpcCall);
    }
    let b64_min = (byte_size * 4 + 2) / 3;
    let b64_max = (b64_min + 3) & !3;
    if value.len() >= b64_min && value.len() <= b64_max {
        if let Ok(val) = base64::decode(value) {
            if val.len() == byte_size {
                return Ok(val);
            }
        }
    }
    return Err(Error::InvalidRpcCall);
}

pub fn insert_or_update_user(conn: &rusqlite::Connection, session_id: &str) -> Result<User, Error> {
    Ok(conn
        .prepare_cached(
            "INSERT INTO users (session_id) VALUES (?) \
             ON CONFLICT DO UPDATE SET last_active = ((julianday('now') - 2440587.5)*86400.0) \
             RETURNING *",
        )
        .map_err(db_error)?
        .query_row(params![&session_id], User::from_row)
        .map_err(db_error)?)
}

// Validates a (backwards compat) token string.
pub fn get_user_from_token(
    conn: &rusqlite::Connection,
    auth_token_str: &str,
) -> Result<User, Error> {
    let auth_token =
        decode_hex_or_b64(auth_token_str, TOKEN_SIZE).map_err(|_| Error::NoAuthToken)?;
    if auth_token[0] != 0x05 {
        return Err(Error::NoAuthToken);
    }
    let (session_id_bytes, sig_bytes) =
        (&auth_token[0..TOKEN_ID_SIZE], &auth_token[TOKEN_ID_SIZE..]);
    let session_id = hex::encode(session_id_bytes);
    let sig = ed25519_dalek::Signature::try_from(sig_bytes).map_err(|_| Error::NoAuthToken)?;
    if let Err(sigerr) =
        crypto::verify_signature(&crypto::TOKEN_SIGNING_KEYS.public, &sig, &[session_id_bytes])
    {
        warn!("Deprecated token signature verification failed for {}: {:?}", session_id, sigerr);
        return Err(Error::NoAuthToken);
    }
    insert_or_update_user(conn, &session_id)
}

pub fn get_auth_token_challenge(public_key: &str) -> Result<models::Challenge, Rejection> {
    // Doesn't return a response directly for testing purposes

    require_session_id(public_key)?;

    let session_bytes = hex::decode(public_key).unwrap();
    let sig = crypto::TOKEN_SIGNING_KEYS.sign(&session_bytes);

    let mut token = Vec::<u8>::new();
    token.reserve_exact(TOKEN_SIZE);
    token.extend_from_slice(&session_bytes);
    token.extend_from_slice(sig.as_ref());

    if token.len() != TOKEN_SIZE {
        panic!("Internal error! unexpected generated token size");
    }

    // Chop off the leading 0x05, the rest is the x25519 pubkey
    let pk_bytes = &session_bytes[1..];

    // Generate an ephemeral key pair
    let (ephemeral_private_key, ephemeral_public_key) = crypto::generate_x25519_key_pair();
    // Generate a symmetric key from the requesting user's public key and the ephemeral private key
    let symmetric_key = crypto::get_x25519_symmetric_key(&pk_bytes, &ephemeral_private_key)?;

    // Encrypt the token with the symmetric key
    let ciphertext = crypto::encrypt_aes_gcm(&token, &symmetric_key)?;
    // Return
    Ok(models::Challenge {
        ciphertext: base64::encode(ciphertext),
        ephemeral_public_key: base64::encode(ephemeral_public_key.to_bytes()),
    })
}

// Message sending & receiving

// FIXME TODO - needs a flag to control whether it returns in new Message format instead of
// OldMessage

/// Inserts a message into the database.
pub fn insert_message(
    room: Room,
    user: User,
    data: &[u8],
    signature: &[u8],
) -> Result<Response, Rejection> {
    let mut conn = storage::get_conn()?;
    let tx = storage::get_transaction(&mut conn)?;
    require_authorization(
        &tx,
        &user,
        &room,
        AuthorizationRequired { write: true, ..Default::default() },
    )?;

    // Check if the requesting user needs to be rate limited

    let now_secs = unixtime_f64() - RATE_LIMIT_INTERVAL as f64;

    let recent_posts: i64 = tx
        .prepare_cached("SELECT COUNT(*) FROM messages WHERE room = ? AND user = ? AND posted >= ?")
        .map_err(db_error)?
        .query_row(params![room.id, user.id, now_secs], |row| row.get(0))
        .map_err(db_error)?;
    if recent_posts >= RATE_LIMIT_POSTS {
        return Err(warp::reject::custom(Error::RateLimited));
    }

    // Don't store useless padding; we'll repad (since it's needed for signature verification) when
    // we retrieve.
    let size = data.len();
    let trimmed = match data.iter().rposition(|&c| c != 0u8) {
        Some(last) => &data[0..=last],
        None => &data,
    };

    // Insert the message
    let message = match tx
        .prepare_cached(
            "INSERT INTO messages (room, user, data, data_size, signature) \
             VALUES (?, ?, ?, ?, ?) \
             RETURNING *",
        )
        .map_err(db_error)?
        .query_row(params![room.id, user.id, trimmed, size, signature], OldMessage::from_row)
    {
        Ok(m) => m,
        Err(e) => {
            error!("Couldn't insert message: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };

    // Commit
    if let Err(e) = tx.commit() {
        error!("Failed to commit message: {}", e);
        return Err(warp::reject::custom(Error::DatabaseFailedInternally));
    }

    let response = json!({ "status_code": StatusCode::OK.as_u16(), "message": message });
    Ok(warp::reply::json(&response).into_response())
}

// TODO FIXME: The paging mechanism here is really odd: you can either get the last 256 messages,
// *or* you can start getting messages from the beginning of time and walk forward.  This is
// really, really inefficient, though, because if you join a very old room you could end up having
// to load the entire history from the beginning of time if you want to scroll back before the
// 256th-last message.
//
// (The same applies to get_deleted_messages, below).

fn get_messages_params(query_params: &HashMap<String, String>) -> (Option<i64>, u16) {
    let from_server_id: Option<i64>;
    if let Some(str) = query_params.get("from_server_id") {
        from_server_id = str.parse::<i64>().ok();
    } else {
        from_server_id = None;
    }
    let limit: u16; // Never return more than 256 messages at once
    if let Some(str) = query_params.get("limit") {
        limit = std::cmp::min(str.parse().unwrap_or(256), 256);
    } else {
        limit = 256;
    }

    return (from_server_id, limit);
}

// FIXME: need something similar that returns new message format

/// Returns either the last `limit` messages or all messages since `from_server_id`, limited to
/// `limit`.
pub fn get_messages(
    query_params: HashMap<String, String>,
    user: User,
    room: Room,
) -> Result<Vec<OldMessage>, Rejection> {
    let conn = storage::get_conn()?;

    require_authorization(
        &conn,
        &user,
        &room,
        AuthorizationRequired { read: true, ..Default::default() },
    )?;

    let (from_server_id, limit) = get_messages_params(&query_params);

    let query = format!(
        "SELECT messages.*, user.session_id FROM messages JOIN users ON messages.user = users.id \
         WHERE data IS NOT NULL {} ORDER BY id {} LIMIT ?2",
        if from_server_id.is_some() { "AND id > ?1" } else { "" },
        if from_server_id.is_some() { "ASC" } else { "DESC" }
    );
    let result = match conn
        .prepare_cached(&query)
        .map_err(db_error)?
        .query_map(params![from_server_id, limit], OldMessage::from_row)
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get messages: {}.", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    }
    .collect::<Result<Vec<OldMessage>, _>>()
    .map_err(|_| Error::DatabaseFailedInternally.into());
    return result;
}

// Message deletion

/// Deletes the messages with the given `ids` from the database, if present.
pub fn delete_messages(ids: Vec<i64>, user: &User, room: &Room) -> Result<Response, Rejection> {
    let mut conn = storage::get_conn()?;
    let tx = storage::get_transaction(&mut conn)?;

    for id in ids {
        delete_message(&tx, id, &user, &room)?;
    }

    tx.commit().map_err(db_error)?;

    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    Ok(warp::reply::json(&json).into_response())
}

/// Deletes the message with the given `id` from the database, if it's present.
pub fn delete_message(
    conn: &rusqlite::Connection,
    id: i64,
    user: &User,
    room: &Room,
) -> Result<Response, Rejection> {
    let mut auth_req = AuthorizationRequired { read: true, ..Default::default() };

    // Check to see if the message to be deleted is owned by someone else: if it is, we require
    // moderator access for the deletion.
    let mut st = conn
        .prepare_cached("SELECT COUNT(*) FROM messages WHERE room = ? AND id = ? AND user != ?")
        .map_err(db_error)?;

    match st.query_row(params![room.id, id, user.id], |row| row.get::<_, i64>(0)) {
        Ok(count) => {
            if count > 0 {
                auth_req.moderator = true;
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            let response = json!({"status_code": StatusCode::NOT_FOUND.as_u16()});
            return Ok(warp::reply::json(&response).into_response());
        }
        Err(_) => return Err(Error::DatabaseFailedInternally.into()),
    };

    require_authorization(conn, user, room, auth_req)?;

    let mut del_st = conn
        .prepare_cached(
            "UPDATE messages SET data = NULL, data_size = NULL, signature = NULL WHERE id = ?",
        )
        .map_err(db_error)?;

    if let Err(e) = del_st.execute(params![id]) {
        error!("Couldn't delete message: {}.", e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    Ok(warp::reply::json(&json).into_response())
}

// TODO FIXME -- the paging here is odd.  See get_messages for details.

/// Returns either the last `limit` deleted messages or all deleted messages since
/// `from_server_id`, limited to `limit`.
pub fn get_deleted_messages(
    query_params: HashMap<String, String>,
    user: User,
    room: Room,
) -> Result<Vec<models::DeletedMessage>, Rejection> {
    let conn = storage::get_conn()?;

    let (from_server_id, limit) = get_messages_params(&query_params);

    require_authorization(
        &conn,
        &user,
        &room,
        AuthorizationRequired { read: true, ..Default::default() },
    )?;

    // Query the database
    let mut st = conn.prepare_cached(if from_server_id.is_some() {
            "SELECT updated, id FROM messages WHERE room = ?1 AND updated > ?2 AND data IS NULL ORDER BY updated LIMIT ?3"
        } else {
            "SELECT updated, id FROM messages WHERE room = ?1 AND data IS NULL ORDER BY updated DESC LIMIT ?3"
        }).map_err(db_error)?;
    let result = match st.query_map(params![from_server_id, limit], |row| {
        Ok(models::DeletedMessage { updated: row.get(0)?, deleted_message_id: row.get(1)? })
    }) {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't get deleted messages: {}.", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    }
    .collect::<Result<Vec<models::DeletedMessage>, _>>()
    .map_err(|_| Error::DatabaseFailedInternally.into());
    return result;
}

// Moderation

pub fn add_moderator_public(
    room: Room,
    user: User,
    session_id: &str,
    admin: bool,
) -> Result<Response, Rejection> {
    require_authorization(
        &*storage::get_conn()?,
        &user,
        &room,
        AuthorizationRequired { admin: true, ..Default::default() },
    )?;
    add_moderator_impl(session_id, admin, room)
}

// TODO: need ability to add *global* server moderators/admins (which, of course, can only be done
// by global server admins).

// Not publicly exposed.
pub async fn add_moderator(
    body: models::ChangeModeratorRequestBody,
) -> Result<Response, Rejection> {
    add_moderator_impl(
        &body.session_id,
        body.admin.unwrap_or(false),
        storage::get_room_from_token(&*storage::get_conn()?, &body.room_token)?,
    )
}

pub fn add_moderator_impl(
    session_id: &str,
    admin: bool,
    room: Room,
) -> Result<Response, Rejection> {
    require_session_id(session_id)?;

    let mut conn = storage::get_conn()?;
    let tx = storage::get_transaction(&mut conn)?;

    if let Err(e) = tx
        .prepare_cached("INSERT OR IGNORE INTO users (session_id) VALUES (?)")
        .map_err(db_error)?
        .execute(params![session_id])
    {
        error!("Failed to insert new user row for {}: {}", session_id, e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    let add_perm_query = format!(
        "INSERT INTO user_permission_overrides (user, room, {mod_column})
         VALUES ((SELECT id FROM users WHERE session_id = ?), ?, TRUE)
         ON CONFLICT DO UPDATE SET {mod_column} = TRUE",
        mod_column = if admin { "admin" } else { "moderator" }
    );
    if let Err(e) =
        tx.prepare_cached(&add_perm_query).map_err(db_error)?.execute(params![session_id, room.id])
    {
        error!("Failed to insert new permission for {}: {}", session_id, e);
        return Err(Error::DatabaseFailedInternally.into());
    }
    if let Err(e) = tx.commit() {
        error!("Failed to commit new moderator transaction: {}", e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    // Return
    info!("Added moderator: {} to room with ID: {}", &session_id, &room.token);
    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    Ok(warp::reply::json(&json).into_response())
}

pub fn delete_moderator_public(
    session_id: &str,
    user: User,
    room: Room,
) -> Result<Response, Rejection> {
    require_authorization(
        &*storage::get_conn()?,
        &user,
        &room,
        AuthorizationRequired { admin: true, ..Default::default() },
    )?;
    delete_moderator_impl(session_id, room)
}

// Not publicly exposed.
pub async fn delete_moderator(
    body: models::ChangeModeratorRequestBody,
) -> Result<Response, Rejection> {
    delete_moderator_impl(
        &body.session_id,
        storage::get_room_from_token(&*storage::get_conn()?, &body.room_token)?,
    )
}

pub fn delete_moderator_impl(session_id: &str, room: Room) -> Result<Response, Rejection> {
    require_session_id(session_id)?;

    let conn = storage::get_conn()?;
    let mut st = conn
        .prepare_cached(
            "UPDATE user_permission_overrides SET moderator = FALSE, admin = FALSE \
             WHERE room = ? AND user = (SELECT id FROM users WHERE session_id = ?) AND (moderator OR admin)"
        )
        .map_err(db_error)?;
    match st.execute(params![room.id, &session_id]) {
        Err(e) => {
            error!("Couldn't remove moderator {} from room {}: {}", session_id, room.token, e);
            return Err(Error::DatabaseFailedInternally.into());
        }
        Ok(count) if count > 0 => {
            info!("Removed moderator {} from room {}", session_id, room.token)
        }
        Ok(_count) => info!("{} is not a moderator of room {}", session_id, room.token),
    }

    let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
    Ok(warp::reply::json(&json).into_response())
}

/// Returns the list of a room's publicly visible moderators (including admins).
pub fn get_moderators(
    conn: &rusqlite::Connection,
    user: &User,
    room: &Room,
) -> Result<Vec<String>, Rejection> {
    require_authorization(
        conn,
        user,
        room,
        AuthorizationRequired { read: true, ..Default::default() },
    )?;

    let mut st = conn
        .prepare_cached(
            "SELECT session_id FROM user_permissions WHERE room = ? AND moderator AND visible_mod",
        )
        .map_err(db_error)?;

    let ids: Result<Vec<String>, _> = match st.query_map(params![room.id], |row| row.get(0)) {
        Ok(row) => row,
        Err(e) => {
            error!("Couldn't query database: {}.", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    }
    .collect();
    ids.map_err(|_| Error::DatabaseFailedInternally.into())
}

// FIXME: we also need server-level ban controls, along with message deletion abilities.

// FIXME: we need the ability to remove read/write/upload permissions without banning.

// FIXME: we need an ability to set a time-expiring limitation

/// Bans the given `public_key`, optionally also deleting all the user's messages and uploaded
/// files.  Requires a moderator for a regular user, and admin for a moderator/admin.
pub async fn ban(
    session_id: &str,
    delete_all: bool,
    user: &User,
    room: &Room,
) -> Result<Response, Rejection> {
    if !is_session_id(&session_id) {
        warn!("Ignoring ban request: invalid session_id.");
        return Err(Error::ValidationFailed.into());
    }

    let mut auth = AuthorizationRequired { moderator: true, ..Default::default() };

    let mut conn = storage::get_conn()?;
    let tx = storage::get_transaction(&mut conn)?;

    tx.prepare_cached("INSERT OR IGNORE INTO users (session_id) VALUES (?)")
        .map_err(db_error)?
        .execute(params![session_id])
        .map_err(db_error)?;

    let userid: i64;

    match tx
        .prepare_cached(
            "SELECT user, moderator, global_moderator FROM user_permissions \
            WHERE room = ? AND session_id = ?",
        )
        .map_err(db_error)?
        .query_row(params![room.id, session_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
    {
        Ok((uid, is_mod, is_global_mod)) => {
            if is_global_mod {
                warn!("Cannot ban {} from {}: user is a global moderator", session_id, room.token);
                return Err(Error::Unauthorized.into());
            }
            userid = uid;
            if is_mod {
                // To ban a moderator we have to be a room admin, not just a moderator.
                auth.admin = true;
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            let response = json!({"status_code": StatusCode::NOT_FOUND.as_u16()});
            return Ok(warp::reply::json(&response).into_response());
        }
        Err(_) => return Err(Error::DatabaseFailedInternally.into()),
    };

    require_authorization(&tx, user, room, auth)?;

    if let Err(e) = tx
        .prepare_cached(
            "\
            INSERT INTO user_permission_overrides (room, user, banned, moderator, admin) \
            VALUES (?, ?, TRUE, FALSE, FALSE) \
            ON CONFLICT DO UPDATE SET banned = TRUE, moderator = FALSE, admin = FALSE
            ",
        )
        .map_err(db_error)?
        .execute(params![room.id, userid])
    {
        error!("Failed to insert ban for {} in {}: {}", session_id, room.token, e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    let mut posts_removed = 0;
    let mut files_removed = 0;
    if delete_all {
        posts_removed += match tx
            .prepare_cached(
                "UPDATE messages SET data = NULL, data_size = NULL, signature = NULL \
                WHERE room = ? AND user = ?",
            )
            .map_err(db_error)?
            .execute(params![room.id, userid])
        {
            Ok(count) => count,
            Err(e) => {
                error!("Failed to delete posts by {} from {}: {}", session_id, room.token, e);
                return Err(Error::DatabaseFailedInternally.into());
            }
        };

        // We don't actually delete from disk right now, but clear the room (so that they aren't
        // retrievable) and set them to be expired (so that the next file pruning will delete them
        // from disk).
        files_removed = tx
            .prepare_cached(
                "UPDATE files SET room = NULL, expiry = ? WHERE room = ? AND uploader = ?",
            )
            .map_err(db_error)?
            .execute(params![unixtime_f64(), room.id, userid])
            .map_err(db_error)?;
    }

    if let Err(e) = tx.commit() {
        info!("Failed to ban/delete user {} from {}: {}", session_id, room.token, e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    info!(
        "Banned {} from room {}: {} messages and {} files deleted",
        session_id, room.token, posts_removed, files_removed
    );

    Ok(warp::reply::json(&models::StatusCode { status_code: StatusCode::OK.as_u16() })
        .into_response())
}

/// Unbans the given `public_key` if the requesting user is a moderator.
pub fn unban(session_id: &str, user: &User, room: &Room) -> Result<Response, Rejection> {
    if !is_session_id(&session_id) {
        warn!("Ignoring unban request: invalid session_id.");
        return Err(Error::ValidationFailed.into());
    }

    let conn = storage::get_conn()?;
    require_authorization(
        &conn,
        user,
        room,
        AuthorizationRequired { moderator: true, ..Default::default() },
    )?;

    let count = match conn
        .prepare_cached(
            "UPDATE user_permission_overrides SET banned = FALSE \
            WHERE room = ? AND user IN (SELECT id FROM users WHERE session_id = ?)",
        )
        .map_err(db_error)?
        .execute(params![room.id, session_id])
    {
        Ok(count) => count,
        Err(e) => {
            error!("Failed to unban user: {}", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    };

    let status_code =
        if count > 0 { StatusCode::OK.as_u16() } else { StatusCode::NOT_FOUND.as_u16() };
    Ok(warp::reply::json(&models::StatusCode { status_code }).into_response())
}

// FIXME: this list was obtainable by *anyone* with basic access.  This seemed wrong, so I changed
// it to require moderator access to get that list.  We need to verify that doesn't break existing
// Session versions -- and if it does, stick in a hack, perhaps returning an empty list if not a
// moderator.  (Or perhaps a list that can only include yourself, so that you can see your own ban
// but no one else's).

/// Returns the full list of banned public keys.
pub fn get_banned_public_keys(user: &User, room: &Room) -> Result<Response, Rejection> {
    let conn = storage::get_conn()?;
    require_authorization(
        &conn,
        user,
        room,
        AuthorizationRequired { moderator: true, ..Default::default() },
    )?;

    let banned_members: Result<Vec<String>, _> = match conn
        .prepare_cached("SELECT session_id FROM user_permissions WHERE room = ? AND banned")
        .map_err(db_error)?
        .query_map(params![room.id], |row| row.get(0))
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Couldn't query database: {}.", e);
            return Err(Error::DatabaseFailedInternally.into());
        }
    }
    .collect();

    Ok(warp::reply::json(&json!({
        "status_code": StatusCode::OK.as_u16(),
        "banned_members": banned_members.map_err(db_error)?
    }))
    .into_response())
}

// General

/// Returns members who have accessed the given room at least once in the past 7 days.
pub fn get_member_count(user: User, room: Room) -> Result<Response, Rejection> {
    return get_member_count_since(user, room, ROOM_DEFAULT_ACTIVE_THRESHOLD);
}

// FIXME: wire this up in API call so that callers can specify a threshold timeout
pub fn get_member_count_since(
    user: User,
    room: Room,
    ago: Duration,
) -> Result<Response, Rejection> {
    let conn = storage::get_conn()?;
    require_authorization(
        &conn,
        &user,
        &room,
        AuthorizationRequired { read: true, ..Default::default() },
    )?;

    let mut st = conn
        .prepare_cached("SELECT COUNT(*) FROM room_users WHERE room = ? AND last_active >= ?")
        .map_err(db_error)?;
    let cutoff =
        (SystemTime::now() - ago).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();
    let users = match st.query_row(params![room.id, cutoff], |row| Ok(row.get::<_, i64>(0)?)) {
        Ok(count) => count,
        Err(e) => {
            error!("Couldn't query database: {}.", e);
            return Err(warp::reject::custom(Error::DatabaseFailedInternally));
        }
    };
    let response = json!({ "status_code": StatusCode::OK.as_u16(), "member_count": users });
    Ok(warp::reply::json(&response).into_response())
}

/// Polls a room for metadata (name, description, image, moderators) if metadata has been updated
/// since the given update value (or always, if since_update is omitted).
pub fn poll_room_metadata(user: &User, room: Room, since_update: Option<i64>) {
    // FIXME TODO
    todo!("FIXME TODO");
}

/// Polls a room for new/updated/deleted messages posted since a given update id.
pub fn get_room_updates(user: User, room: Room, since_update: i64) {
    // FIXME TODO - implement this
    todo!("FIXME TODO");

    /*
    debug!("Got unified poll request for room {} since update {}", room.token, since);
    response.messages = get_msg_updates.query_map(params![room.id, since], Message::from_row)
        .map_err(db_error)?
        .collect::<Result<Vec<models::Message>, _>>()
        .map_err(db_error)?;

    // Gets a list of new, updated, and deleted messages since a given room update value.
    let mut get_msg_updates = tx.prepare_cached(
        "SELECT * FROM message_details WHERE room = ? AND updated > ? ORDER BY updated LIMIT 250")
        .map_err(db_error)?;

    */
}

/// Deprecated room polling; unlike the above, this does not handle metadata (except for
/// moderators, which are *always* included even though they rarely change), does not support
/// message edits, and has non-obvious alternate modes of operation.
pub fn compact_poll(
    user: Option<User>,
    request_bodies: Vec<models::CompactPollRequestBody>,
) -> Result<Response, Rejection> {
    let mut response_bodies = Vec::<models::CompactPollResponseBody>::new();

    let mut conn = storage::get_conn()?;
    let tx = storage::get_transaction(&mut conn)?;

    let mut rooms = HashMap::<String, Option<Room>>::new();
    for r in &request_bodies {
        rooms.insert(r.room_token.clone(), None);
    }

    if !rooms.is_empty() {
        let query =
            format!("SELECT * FROM rooms WHERE token IN (?{})", ",?".repeat(rooms.len() - 1));
        for r in tx
            .prepare_cached(&query)
            .map_err(db_error)?
            .query_map(params_from_iter(rooms.keys()), Room::from_row)
            .map_err(db_error)?
        {
            let room = r.map_err(db_error)?;
            rooms.insert(room.token.clone(), Some(room));
        }
    }

    {
        // Gets a list of recent room messages: Session fires this when first joining a room.
        let mut get_recent_messages = tx
            .prepare_cached(
                "SELECT * FROM message_details \
                WHERE room = ? AND data IS NOT NULL \
                ORDER BY id DESC LIMIT 256",
            )
            .map_err(db_error)?;

        let mut get_recent_deletions = tx
            .prepare_cached(
                "SELECT id, updated FROM messages \
                WHERE room = ? AND data IS NULL \
                ORDER BY updated DESC LIMIT 256",
            )
            .map_err(db_error)?;

        // Queries for actual polling, where we have an ID
        let mut get_deleted_msgs = tx
            .prepare_cached(
                "SELECT id, updated FROM messages \
                WHERE room = ? AND updated > ? AND data IS NULL \
                ORDER BY updated LIMIT 256",
            )
            .map_err(db_error)?;

        let mut get_msgs_since = tx
            .prepare_cached(
                "SELECT * FROM message_details \
                WHERE room = ? AND id > ? AND data IS NOT NULL \
                ORDER BY id LIMIT 256",
            )
            .map_err(db_error)?;

        for request in request_bodies {
            let mut response = models::CompactPollResponseBody {
                room_token: request.room_token.clone(),
                status_code: StatusCode::OK.as_u16(),
                messages: vec![],
                deletions: vec![],
                moderators: vec![],
            };

            let room: &Room = match rooms.get(&request.room_token) {
                Some(Some(room)) => room,
                _ => {
                    response.status_code = StatusCode::NOT_FOUND.as_u16();
                    response_bodies.push(response);
                    continue;
                }
            };

            let token_user: User;
            let user = match user {
                Some(ref u) => &u,
                None => {
                    token_user =
                        get_user_from_token(&tx, &request.auth_token.ok_or(Error::Unauthorized)?)?;
                    &token_user
                }
            };

            // Require read authorization, otherwise return a failure response for this
            // sub-request.
            let read_auth = AuthorizationRequired { read: true, ..Default::default() };
            if let Err(e) = require_authorization(&tx, &user, &room, read_auth) {
                response.status_code = super::errors::status_code(e.into()).as_u16();
                response_bodies.push(response);
                continue;
            }

            // Older Session clients ask us for messages since some ID & deletions since some
            // deletion ID, and can't handle edits at all:
            response.messages = if let Some(mut since) = request.from_message_server_id {
                debug!(
                    "Got deprecated poll request for room {} messages since {}",
                    room.token, since
                );
                // If this is an imported database then we might have room id maps for "since-id"
                // requests made from a client before the migration, and if so, we need to offset
                // the requested id.
                if let Some(hacks) = storage::ROOM_IMPORT_HACKS.as_ref() {
                    if let Some(map) = hacks.get(&room.id) {
                        if since <= map.max {
                            since += map.offset;
                        }
                    }
                }
                get_msgs_since.query_map(params![room.id, since], OldMessage::from_row)
            } else {
                debug!(
                    "Deprecated request without from; returning recent messages for {}",
                    room.token
                );
                get_recent_messages.query_map(params![room.id], OldMessage::from_row)
            }
            .map_err(db_error)?
            .collect::<Result<Vec<models::OldMessage>, _>>()
            .map_err(db_error)?;

            let make_delmsg = |row: &rusqlite::Row| {
                Ok(models::DeletedMessage { deleted_message_id: row.get(0)?, updated: row.get(1)? })
            };

            response.deletions = match request.from_deletion_server_id {
                Some(since) => {
                    debug!("Deprecated poll request for {} deletions since {}", room.token, since);
                    get_deleted_msgs.query_map(params![room.id, since], make_delmsg)
                }
                _ => {
                    debug!("Deprecated poll request for recent {} deletions", room.token);
                    get_recent_deletions.query_map(params![room.id], make_delmsg)
                }
            }
            .map_err(db_error)?
            .collect::<Result<Vec<models::DeletedMessage>, _>>()
            .map_err(db_error)?;

            // Get the moderators.
            response.moderators = match get_moderators(&tx, &user, &room) {
                Ok(moderators) => moderators,
                Err(e) => {
                    response.status_code = super::errors::status_code(e).as_u16();
                    response_bodies.push(response);
                    continue;
                }
            };
            // We *also* include the requesting user if she is a global moderator/admin -- this
            // isn't part of the room's moderator list, but older Session relies on seeing itself
            // in this list to enable moderator capabilities.
            if user.moderator || user.admin {
                response.moderators.push(user.session_id.clone());
            }

            response_bodies.push(response);
        }
    }

    if let Err(e) = tx.commit() {
        error!("Compact poll queries failed: {}", e);
        return Err(Error::DatabaseFailedInternally.into());
    }

    let response = json!({ "status_code": StatusCode::OK.as_u16(), "results": response_bodies });
    Ok(warp::reply::json(&response).into_response())
}

// Not publicly exposed.
pub async fn get_url() -> Result<Response, Rejection> {
    let url = super::get_url();
    Ok(warp::reply::json(&url).into_response())
}

pub async fn get_session_version(platform: &str) -> Result<String, Rejection> {
    let mut session_versions = SESSION_VERSIONS.read().clone();
    let now = chrono::Utc::now().timestamp();
    if let Some(version_info) = session_versions.get(platform) {
        let last_updated = version_info.0;
        if now - last_updated < SESSION_VERSION_UPDATE_INTERVAL {
            let tag = version_info.1.to_string();
            println!("Returning cached value: {}", tag);
            return Ok(tag);
        }
    }
    let octocrab = octocrab::instance();
    let repo = format!("session-{}", platform);
    let handler = octocrab.repos("oxen-io", repo);
    let release = handler.releases().get_latest().await.unwrap();
    let tag = release.tag_name;
    let tuple = (now, tag.clone());
    session_versions.insert(platform.to_string(), tuple);
    *SESSION_VERSIONS.write() = session_versions.clone();
    Ok(tag)
}

// not publicly exposed.
pub async fn get_stats_for_room(
    room_token: String,
    query_map: HashMap<String, i64>,
) -> Result<Response, Rejection> {
    let window = *query_map.get("window").unwrap_or(&3600) as f64;
    let upperbound = match query_map.get("start") {
        Some(ts) => *ts as f64,
        None => unixtime_f64(),
    };
    let lowerbound = upperbound - window;

    let mut conn = storage::get_conn()?;
    let tx = storage::get_transaction(&mut conn)?;

    let room = storage::get_room_from_token(&tx, &room_token)?;

    let active = tx
        .prepare_cached(
            "SELECT COUNT(*) FROM room_users WHERE room = ? AND last_active BETWEEN ? AND ?",
        )
        .map_err(db_error)?
        .query_row(params![room.id, lowerbound, upperbound], |row| Ok(row.get::<_, i64>(0)?))
        .map_err(db_error)?;

    let posts = tx
        .prepare_cached("SELECT COUNT(*) FROM messages WHERE room = ? AND posted BETWEEN ? AND ?")
        .map_err(db_error)?
        .query_row(params![room.id, lowerbound, upperbound], |row| Ok(row.get::<_, i64>(0)?))
        .map_err(db_error)?;

    // FIXME: DRY this structure
    let response = json!({
        "active_users": active,
        "posts": posts });
    Ok(warp::reply::json(&response).into_response())
}

// Utilities

fn is_session_id(session_id: &str) -> bool {
    session_id.len() == 66
        && &session_id[0..2] == "05"
        && session_id.find(|c: char| !c.is_ascii_hexdigit()).is_none()
}

pub fn require_session_id(session_id: &str) -> Result<(), Error> {
    if !is_session_id(session_id) {
        warn!("'{}' is not a valid Session id", session_id);
        return Err(Error::ValidationFailed);
    }
    return Ok(());
}

/// Verify that the user has the given permissions for the given room (and isn't banned), and
/// updates the last activity record for the user in the room.  Returns an Error::Unauthorized if
/// the user does not have the required permissions, Error::DatabaseFailedInternally on database
/// error, and an empty tuple on success.
///
/// `conn` is expected to be either a connection or an open transaction.
fn require_authorization(
    conn: &rusqlite::Connection,
    user: &User,
    room: &Room,
    req: AuthorizationRequired,
) -> Result<(), Error> {
    require_authorization_impl(conn, &user, &room, req, true)
}
/// Same as above, but does not update the room/user last activity timestamp.
#[allow(dead_code)]
fn require_authorization_no_activity(
    conn: &rusqlite::Connection,
    user: &User,
    room: &Room,
    req: AuthorizationRequired,
) -> Result<(), Error> {
    return require_authorization_impl(conn, &user, &room, req, false);
}

fn require_authorization_impl(
    conn: &rusqlite::Connection,
    user: &User,
    room: &Room,
    need: AuthorizationRequired,
    log_active: bool,
) -> Result<(), Error> {
    let mut st = conn
        .prepare_cached(
            "SELECT banned, read, write, upload, moderator, admin FROM user_permissions WHERE room = ? AND user = ?"
        )
        .map_err(db_error)?;

    match st.query_row(params![room.id, user.id], |row| {
        let banned: bool = row.get(0)?;
        let read: bool = row.get(1)?;
        let write: bool = row.get(2)?;
        let upload: bool = row.get(3)?;
        let moderator: bool = row.get(4)?;
        let admin: bool = row.get(5)?;
        return Ok(if admin {
            true
        } else if need.admin {
            false
        } else if moderator {
            true
        } else if need.moderator {
            false
        } else {
            !banned && (!need.read || read) && (!need.write || write) && (!need.upload || upload)
        });
    }) {
        Ok(allowed) => {
            if !allowed {
                return Err(Error::Unauthorized);
            }
        }
        Err(e) => {
            error!("Couldn't query permissions from database: {}", e);
            return Err(Error::DatabaseFailedInternally);
        }
    };

    if log_active {
        conn.prepare_cached(
            "INSERT INTO room_users (user, room) VALUES (?, ?)
                            ON CONFLICT DO UPDATE SET last_active = ((julianday('now') - 2440587.5)*86400.0)"
        )
        .map_err(db_error)?
        .execute(params![user.id, room.id])
        .map_err(db_error)?;
    }
    Ok(())
}

fn unixtime_f64() -> f64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64()
}
