use std::collections::HashMap;

use ed25519_dalek;
use log::warn;
use serde::Deserialize;
use serde_json::json;
use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

use super::crypto;
use super::errors::Error;
use super::handlers;
use super::models::{self, Room, User};
use super::storage;

#[allow(dead_code)]
pub enum Mode {
    FileServer,
    OpenGroupServer
}

#[derive(Deserialize, Debug)]
pub struct RpcCall {
    pub endpoint: String,
    pub body: String,
    pub method: String,
    // TODO: deprecate headers; currently it only ever contains Authorization (for a deprecated
    // token) and Room, which we should replace by encoding the room token in the endpoint.
    pub headers: HashMap<String, String>,

    // For new, token-less requests; requests without these should be considered deprecated.
    /// Ed25519 pubkey, in hex (will be used to derive the Session key by converting and prepending
    /// 05).
    pub ed25519_pubkey: Option<String>,
    /// Arbitrary string; must be different on each request
    pub nonce: Option<String>,
    /// Ed25519 signature (in base64 or hex) of (method || endpoint || body || nonce)
    pub signature: Option<String>
}

pub const MODE: Mode = Mode::OpenGroupServer;

// Gets a user from a reflected auth token.  Returns None if there is no auth token, User if there
// is a parseable auth token, and an error for anything else.
fn get_user_from_auth_header(
    conn: &rusqlite::Connection,
    rpc: &RpcCall
) -> Result<Option<User>, Error>
{
    if let Some(auth_token_str) = rpc.headers.get("Authorization") {
        return Ok(Some(handlers::get_user_from_token(conn, auth_token_str)?));
    }
    return Ok(None);
}

// FIXME TODO - these calls using warp::Rejection as an error type are Doing It Wrong:
// warp::Rejection means "decline this handler, try another one" but everywhere we are using it we
// mean "return an error".
//
// c.f. https://github.com/seanmonstar/warp/issues/388

pub async fn handle_rpc_call(mut rpc_call: RpcCall) -> Result<Response, Rejection> {
    let have_sig = rpc_call.ed25519_pubkey.is_some();
    if rpc_call.nonce.is_some() != have_sig || rpc_call.signature.is_some() != have_sig {
        warn!(
            "Invalid request: all or none of {{ed25519_pubkey, nonce, signature}} must be provided"
        );
        return Err(Error::InvalidRpcCall.into());
    }

    let mut user: Option<User> = None;
    if have_sig {
        let (edpk, _xpk, sessionid) =
            crypto::get_pubkeys(rpc_call.ed25519_pubkey.as_ref().unwrap())?;

        let nonce = rpc_call.nonce.as_ref().unwrap();
        // TODO FIXME: reject recent pubkey/nonce combinations.

        let mut sig_bytes: [u8; 64] = [0; 64];
        sig_bytes.copy_from_slice(
            &handlers::decode_hex_or_b64(rpc_call.signature.as_ref().unwrap(), 64)?[0..64]
        );
        let sig = ed25519_dalek::Signature::new(sig_bytes);

        if let Err(sigerr) = handlers::verify_signature(&edpk, &sig, &vec![
            rpc_call.endpoint.as_bytes(),
            rpc_call.method.as_bytes(),
            rpc_call.body.as_bytes(),
            nonce.as_bytes(),
        ]) {
            warn!("Signature verification failed for request from {}", sessionid);
            return Err(sigerr.into());
        }

        user = Some(handlers::insert_or_update_user(&*storage::get_conn()?, &sessionid)?);

        // Check for a global ban, and if so, terminate the request right away.
        if user.as_ref().unwrap().banned {
            return Err(Error::Unauthorized.into());
        }
    }

    // Check that the endpoint is a valid URI and deconstruct it into a path
    // and query parameters.
    if !rpc_call.endpoint.starts_with('/') {
        rpc_call.endpoint = format!("/{}", rpc_call.endpoint);
    }
    let path: String;
    let query_params: HashMap<String, String>;
    match rpc_call.endpoint.parse::<http::Uri>() {
        Ok(uri) => {
            path = uri.path().trim_start_matches('/').to_string();
            query_params = match uri.query() {
                Some(qs) => form_urlencoded::parse(qs.as_bytes()).into_owned().collect(),
                None => HashMap::new()
            };
        }
        Err(e) => {
            warn!("Couldn't parse URI from '{}': {}.", &rpc_call.endpoint, e);
            return Err(Error::InvalidRpcCall.into());
        }
    };

    // TODO FIXME: rather than get the room from a header, here, we should consistently rewrite
    // urls to include the room identifier, e.g. POST /r/room123/message (or similar), and handle
    // that in the handle_xxx_request.

    // Get the room and check that it exists, if a room is provided
    let room = get_room(&rpc_call)?;

    // Get the user from an auth token (and we are not using signed requests, in which case we
    // already know the user).
    if room.is_some() && user.is_none() {
        user = get_user_from_auth_header(&*storage::get_conn()?, &rpc_call)?;
    }

    // Switch on the HTTP method
    match rpc_call.method.as_ref() {
        "GET" => return handle_get_request(room, rpc_call, &path, user, query_params).await,
        "POST" => return handle_post_request(room, rpc_call, &path, user).await,
        "DELETE" => {
            return handle_delete_request(room.ok_or(Error::NoSuchRoom)?, rpc_call, &path, user)
                .await
        }
        _ => {
            warn!("Ignoring RPC call with invalid or unused HTTP method: {}.", rpc_call.method);
            return Err(Error::InvalidRpcCall.into());
        }
    }
}

async fn handle_get_request(
    room: Option<Room>,
    rpc_call: RpcCall,
    path: &str,
    user: Option<User>,
    query_params: HashMap<String, String>
) -> Result<Response, Rejection>
{
    let mut components: Vec<&str> = path.split('/').collect();
    if components.len() == 0 {
        components.push("");
    }

    // Handle routes that don't require authorization first
    if components[0] == "auth_token_challenge" && components.len() == 1 {
        reject_if_file_server_mode(path)?;
        let challenge = handlers::get_auth_token_challenge(
            query_params.get("public_key").ok_or(Error::InvalidRpcCall)?
        )?;
        let response = json!({ "status_code": StatusCode::OK.as_u16(), "challenge": challenge });
        return Ok(warp::reply::json(&response).into_response());
    }
    // /rooms/* endpoint: Deprecated.
    //
    // Use `GET /rooms` or `GET /r/ROOMID` or `GET /r/ROOMID/file/ID` instead.
    //
    // FIXME TODO
    if components[0] == "rooms" {
        reject_if_file_server_mode(path)?;
        if components.len() == 1 {
            return handlers::get_all_rooms();
        }

        let room_token = components[1];
        let room = match room {
            None => storage::get_room_from_token(&*storage::get_conn()?, room_token)?,
            Some(room) => {
                if room.token != room_token {
                    warn!("Attempt to access /rooms/ROOM with mismatched path/header room tokens");
                    return Err(Error::InvalidRpcCall.into());
                }
                room
            }
        };

        if components.len() == 2 {
            return handlers::get_room(&room);
        } else if components[2] == "image" && components.len() == 3 {
            return handlers::get_room_image(room).await;
        }

        warn!("Invalid endpoint: {}.", rpc_call.endpoint);
        return Err(Error::InvalidRpcCall.into());
    }
    if path.starts_with("session_version") {
        match MODE {
            Mode::OpenGroupServer => {
                warn!("Ignoring RPC call with invalid or unused endpoint: {}.", path);
                return Err(Error::InvalidRpcCall.into());
            }
            Mode::FileServer => ()
        }
        let platform = query_params
            .get("platform")
            .ok_or_else(|| warp::reject::custom(Error::InvalidRpcCall))?;
        let version = handlers::get_session_version(platform).await?;
        let response = handlers::GenericStringResponse {
            status_code: StatusCode::OK.as_u16(),
            result: version
        };
        return Ok(warp::reply::json(&response).into_response());
    }

    if matches!(MODE, Mode::FileServer) && path.starts_with("files") {
        panic!("FIXME -- file server retrieval");
    }

    // Handle routes that require authorization

    let user = user.ok_or(Error::NoAuthToken)?;

    // TODO FIXME: new endpoints:
    // - /r/ROOMID - retrieves room metadata
    //
    // - /r/ROOMID/recent - retrieves recent messages
    //
    // - /r/ROOMID/message/ID - retrieve a message by ID
    //
    // - /r/ROOMID/file/FILEID/filename - retrieve a file by id (the "filename" part is optional and
    //   only suggestive)
    //
    // - /r/ROOMID/moderators - retrieves publicly visible room moderators and admins
    //
    // - /r/ROOMID/moderators/all - retrieves visible + hidden room moderators/admins (requires
    //   moderator permission)
    //
    // - /r/ROOMID/bans - retrieves banned public keys.  The full list is only visible to
    //   moderators; for regular users this will be either empty or include just their own session
    //   ID (if banned).

    // Everything below this point requires a room:
    let room = room.ok_or(Error::NoSuchRoom)?;

    // All of these are deprecated; should be using /r/ROOMID/whatever instead.
    match components[0] {
        "messages" => {
            reject_if_file_server_mode(path)?;
            return Ok(warp::reply::json(&json!({
                "status_code": StatusCode::OK.as_u16(),
                "messages": handlers::get_messages(query_params, user, room)?
            }))
            .into_response());
            // FIXME: can drop `.into_response()` I think?
        }
        "deleted_messages" => {
            reject_if_file_server_mode(path)?;
            let deletions = handlers::get_deleted_messages(query_params, user, room)?;
            let response = json!({ "status_code": StatusCode::OK.as_u16(), "ids": deletions });
            return Ok(warp::reply::json(&response).into_response());
        }
        "files" if components.len() == 2 => {
            if let Ok(file_id) = components[1].parse::<i64>() {
                return handlers::get_file(room, file_id, user);
            }
        }
        "moderators" => {
            reject_if_file_server_mode(path)?;
            let public_keys = handlers::get_moderators(&*storage::get_conn()?, &user, &room)?;
            let response =
                json!({ "status_code": StatusCode::OK.as_u16(), "moderators": public_keys });
            return Ok(warp::reply::json(&response).into_response());
        }
        "block_list" => {
            reject_if_file_server_mode(path)?;
            return handlers::get_banned_public_keys(&user, &room);
        }
        "member_count" => {
            reject_if_file_server_mode(path)?;
            return handlers::get_member_count(user, room);
        }
        _ => {}
    };

    warn!("Ignoring RPC call with invalid or unused endpoint: {}.", rpc_call.endpoint);
    return Err(Error::InvalidRpcCall.into());
}

async fn handle_post_request(
    room: Option<Room>,
    rpc_call: RpcCall,
    path: &str,
    user: Option<User>
) -> Result<Response, Rejection>
{
    // Handle routes that don't require authorization first

    // The compact poll endpoint expects the auth token to be in the request body; not in the
    // headers.
    //
    // TODO FIXME: Deprecated; replace this with a /multi endpoint that takes a list of requests to
    // submit (but rather than be specific to that endpoint, it would allow *any* other endpoints
    // to be invoked).
    if path == "compact_poll" {
        reject_if_file_server_mode(path)?;
        #[derive(Debug, Deserialize)]
        struct CompactPollRequestBodyWrapper {
            requests: Vec<models::CompactPollRequestBody>
        }
        let wrapper: CompactPollRequestBodyWrapper = match serde_json::from_str(&rpc_call.body) {
            Ok(bodies) => bodies,
            Err(e) => {
                warn!(
                    "Couldn't parse compact poll request body wrapper from '{}': {}.",
                    rpc_call.body, e
                );
                return Err(Error::InvalidRpcCall.into());
            }
        };
        return handlers::compact_poll(user, wrapper.requests);
    }

    if path == "files" && matches!(MODE, Mode::FileServer) {
        // This route doesn't requires auth in file server mode
        // TODO FIXME
        panic!("No file server mode");
    }

    // Handle routes that require authorization
    let user = user.ok_or(Error::NoAuthToken)?;

    if path == "rooms" || path.starts_with("rooms/") {
        reject_if_file_server_mode(path)?;
        let components: Vec<&str> = path.split('/').collect(); // Split on subsequent slashes
        if components.len() == 3 && components[2] == "image" {
            #[derive(Debug, Deserialize)]
            struct JSON {
                file: String
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Couldn't parse JSON from '{}': {}.", rpc_call.body, e);
                    return Err(Error::InvalidRpcCall.into());
                }
            };

            // Why does this method pass the room differently than most of the other functions?!
            let room_token = components[1];
            let room = match room {
                None => storage::get_room_from_token(&*storage::get_conn()?, room_token)?,
                Some(room) => {
                    if room.token != room_token {
                        warn!("Attempt to access POST /rooms/ROOM with mismatched path/header room tokens");
                        return Err(Error::InvalidRpcCall.into());
                    }
                    room
                }
            };

            // FIXME TODO: add an input field so that the uploader can pass the filename
            let filename: Option<&str> = None;

            return handlers::set_room_image(room, user, &json.file, filename).await;
        } else {
            warn!("Invalid endpoint: {}.", rpc_call.endpoint);
            return Err(Error::InvalidRpcCall.into());
        }
    }
    // Everything below this port requires a room:
    //
    // FIXME -- "moderators" (which adds a moderator) might be broken by this for older clients
    // because it used to take room_id *both* via the header *and* as a field in request body (and
    // then only used the one in the request body).  If Session is passing both room values then
    // everything should be fine.
    //
    let room = room.ok_or(Error::NoSuchRoom)?;
    match path {
        "messages" => {
            // FIXME TODO - Deprecated, returns old message format.  Rewrite this as
            // `POST /r/ROOMID/message`.
            // FIXME 2: Add a `POST /r/ROOMID/message/ID` for editing a message.
            reject_if_file_server_mode(path)?;
            let message: models::PostMessage = match serde_json::from_str(&rpc_call.body) {
                Ok(message) => message,
                Err(e) => {
                    warn!("Couldn't parse message from '{}': {}.", rpc_call.body, e);
                    return Err(Error::InvalidRpcCall.into());
                }
            };
            return handlers::insert_message(room, user, &message.data, &message.signature);
        }

        "files" => {
            // FIXME TODO - Deprecated; rewrite as `POST /r/ROOMID/file`, make it require a
            // filename
            #[derive(Debug, Deserialize)]
            struct JSON {
                file: String
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Couldn't parse JSON from '{}': {}.", rpc_call.body, e);
                    return Err(Error::InvalidRpcCall.into());
                }
            };

            // FIXME TODO: add an input field so that the uploader can pass the filename
            let filename: Option<&str> = None;

            return handlers::store_file(room, user, &json.file, filename);
        }

        // FIXME: deprecate these next two separate endpoints and replace with a single
        // "/r/ROOMID/ban" endpoint that has a "delete all?" flag, and has options for different
        // types of bans and ban expiries.
        "block_list" => {
            reject_if_file_server_mode(path)?;
            #[derive(Debug, Deserialize)]
            struct JSON {
                public_key: String
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Couldn't parse JSON from '{}': {}.", rpc_call.body, e);
                    return Err(Error::InvalidRpcCall.into());
                }
            };
            return handlers::ban(&json.public_key, false, &user, &room).await;
        }
        "ban_and_delete_all" => {
            reject_if_file_server_mode(path)?;
            #[derive(Debug, Deserialize)]
            struct JSON {
                public_key: String
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Couldn't parse JSON from '{}': {}.", rpc_call.body, e);
                    return Err(Error::InvalidRpcCall.into());
                }
            };
            return handlers::ban(&json.public_key, true, &user, &room).await;
        }
        "claim_auth_token" => {
            // Deprecated; has no purpose anymore (but here for older clients to not get an error)
            // because we're already verified the token (and there are no ephemeral tokens
            // anymore).
            reject_if_file_server_mode(path)?;
            let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
            return Ok(warp::reply::json(&json).into_response());
        }
        "moderators" => {
            // FIXME TODO - Deprecated; Rewrite as /r/ROOMID/moderator and allow it to support new
            // moderator options such as being a hidden mod
            reject_if_file_server_mode(path)?;
            let body: models::ChangeModeratorRequestBody =
                match serde_json::from_str(&rpc_call.body) {
                    Ok(body) => body,
                    Err(e) => {
                        warn!("Couldn't parse JSON from '{}': {}.", rpc_call.body, e);
                        return Err(Error::InvalidRpcCall.into());
                    }
                };
            return handlers::add_moderator_public(
                room,
                user,
                &body.session_id,
                body.admin.unwrap_or(false)
            );
        }
        "delete_messages" => {
            // FIXME TODO - Deprecated; this should be a DELETE /r/ROOMID/ID request, and if we
            // need multiple deletes in one request then should use the POST /multi endpoint to
            // submit them.
            reject_if_file_server_mode(path)?;
            #[derive(Debug, Deserialize)]
            struct JSON {
                ids: Vec<i64>
            }
            let json: JSON = match serde_json::from_str(&rpc_call.body) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Couldn't parse JSON from '{}': {}.", rpc_call.body, e);
                    return Err(Error::InvalidRpcCall.into());
                }
            };
            return handlers::delete_messages(json.ids, &user, &room);
        }
        _ => {
            warn!("Ignoring RPC call with invalid or unused endpoint: {}.", path);
            return Err(Error::InvalidRpcCall.into());
        }
    }
}

async fn handle_delete_request(
    room: Room,
    rpc_call: RpcCall,
    path: &str,
    user: Option<User>
) -> Result<Response, Rejection>
{
    // Check that the auth token is present
    let user = user.ok_or(Error::NoAuthToken)?;
    // DELETE /messages/:server_id
    // FIXME TODO: Deprecated; use DELETE /r/ROOMID/message/ID instead.
    if path.starts_with("messages") {
        reject_if_file_server_mode(path)?;
        let components: Vec<&str> = path.split('/').collect(); // Split on subsequent slashes
        if components.len() != 2 {
            warn!("Invalid endpoint: {}.", path);
            return Err(Error::InvalidRpcCall.into());
        }
        let server_id: i64 = match components[1].parse() {
            Ok(server_id) => server_id,
            Err(_) => {
                warn!("Invalid endpoint: {}.", path);
                return Err(Error::InvalidRpcCall.into());
            }
        };
        return handlers::delete_message(&*storage::get_conn()?, server_id, &user, &room);
    }
    // DELETE /block_list/:public_key
    // FIXME TODO: Deprecated; use DELETE /r/ROOMID/unban/ID instead.
    if path.starts_with("block_list") {
        reject_if_file_server_mode(path)?;
        let components: Vec<&str> = path.split('/').collect(); // Split on subsequent slashes
        if components.len() != 2 {
            warn!("Invalid endpoint: {}.", path);
            return Err(Error::InvalidRpcCall.into());
        }
        let public_key = components[1].to_string();
        return handlers::unban(&public_key, &user, &room);
    }
    // DELETE /auth_token.  Deprecated and does nothing.
    if path == "auth_token" {
        reject_if_file_server_mode(path)?;
        // No-op; this is here for backwards compat with Session clients that try to use auth
        // tokens.
        let json = models::StatusCode { status_code: StatusCode::OK.as_u16() };
        return Ok(warp::reply::json(&json).into_response());
    }
    // DELETE /moderators/:public_key
    // FIXME TODO: Deprecated; use DELETE /r/ROOMID/moderator/SESSIONID
    if path.starts_with("moderators") {
        reject_if_file_server_mode(path)?;
        let components: Vec<&str> = path.split('/').collect(); // Split on subsequent slashes
        if components.len() != 2 {
            warn!("Invalid endpoint: {}.", path);
            return Err(Error::InvalidRpcCall.into());
        }
        let session_id = components[1].to_string();
        let room = match get_room(&rpc_call)? {
            Some(room) => room,
            None => {
                warn!("Missing room ID.");
                return Err(Error::InvalidRpcCall.into());
            }
        };
        return handlers::delete_moderator_public(&session_id, user, room);
    }
    // Unrecognized endpoint
    warn!("Ignoring RPC call with invalid or unused endpoint: {}.", path);
    return Err(Error::InvalidRpcCall.into());
}

// Utilities

fn get_room(rpc_call: &RpcCall) -> Result<Option<Room>, Error> {
    if matches!(MODE, Mode::FileServer) {
        // WTF giant FIXME:
        // In file server mode we don't have a concept of rooms, but for convenience (i.e. so we
        // can use the same database structure) we just always use the main room
        panic!("FIXME");
    }
    assert!(matches!(MODE, Mode::OpenGroupServer));

    if rpc_call.headers.is_empty() {
        return Ok(None);
    }

    let room_token = match rpc_call.headers.get("Room") {
        Some(s) => s,
        None => return Ok(None)
    };
    return Ok(Some(storage::get_room_from_token(&*storage::get_conn()?, room_token)?));
}

fn reject_if_file_server_mode(path: &str) -> Result<(), Rejection> {
    match MODE {
        Mode::FileServer => {
            warn!("Ignoring RPC call with invalid or unused endpoint: {}.", path);
            return Err(Error::InvalidRpcCall.into());
        }
        Mode::OpenGroupServer => return Ok(())
    }
}
