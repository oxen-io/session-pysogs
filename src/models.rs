use base64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub id: i64,
    pub session_id: String,
    pub created: f64,
    pub last_active: f64,
    pub banned: bool,
    pub moderator: bool,
    pub admin: bool
}

impl User {
    pub fn from_row(row: &rusqlite::Row) -> Result<User, rusqlite::Error> {
        return Ok(User {
            id: row.get(row.column_index("id")?)?,
            session_id: row.get(row.column_index("session_id")?)?,
            created: row.get(row.column_index("created")?)?,
            last_active: row.get(row.column_index("last_active")?)?,
            banned: row.get(row.column_index("banned")?)?,
            moderator: row.get(row.column_index("moderator")?)?,
            admin: row.get(row.column_index("admin")?)?
        });
    }
}

fn as_opt_base64<S>(val: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where S: Serializer {
    s.serialize_str(&base64::encode(val.as_ref().unwrap()))
}

/// Old message structure returned by the deprecated compact_poll endpoint.
#[derive(Debug, Serialize)]
pub struct OldMessage {
    /// Server-side message id.  Migration: this becomes `id` in the new Message format.
    pub server_id: i64,
    /// Session id of the poster.  Omitted when the information isn't available/useful (such as
    /// submitting new messages).  Migration: this becomes `session_id` in the new Message format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Timestamp, in unix epoch milliseconds.  Migration: in the new Message format this value is
    /// a floating point value (rather than integer) *and* is returned as actual unix time (i.e.
    /// seconds) rather than milliseconds.
    pub timestamp: i64,
    /// Message data, encoded in base64
    #[serde(serialize_with = "as_opt_base64")]
    pub data: Option<Vec<u8>>,
    /// XEd25519 message signature of the `data` bytes (not the base64 representation), encoded in
    /// base64
    #[serde(serialize_with = "as_opt_base64")]
    pub signature: Option<Vec<u8>>
}

impl OldMessage {
    pub fn from_row(row: &rusqlite::Row) -> Result<OldMessage, rusqlite::Error> {
        let mut data: Option<Vec<u8>> = row.get(row.column_index("data")?)?;
        repad(&mut data, row.get::<_, Option<usize>>(row.column_index("data_size")?)?);
        let session_id = match row.column_index("session_id") {
            Ok(index) => Some(row.get(index)?),
            Err(_) => None
        };
        return Ok(OldMessage {
            server_id: row.get(row.column_index("id")?)?,
            public_key: session_id,
            timestamp: (row.get::<_, f64>(row.column_index("posted")?)? * 1000.0) as i64,
            data,
            signature: row.get(row.column_index("signature")?)?
        });
    }
}


#[derive(Debug, Serialize)]
pub struct Message {
    /// The message id.
    pub id: i64,
    /// The session ID of the user who posted this message, in hex.  Omitted in contexts where the
    /// information isn't available or isn't useful, such as when inserting a message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// unix timestamp of when the message was received on the server.
    pub timestamp: f64,
    /// unix timestamp of when the message was last edited (null if never edited).
    pub edited: Option<f64>,
    /// set to the room's current `updates` value at the time this message was created, last
    /// edited, or deleted.
    pub updated: i64,
    /// The message data, encoded in base64.  This field is omitted if the message is deleted.
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "as_opt_base64")]
    pub data: Option<Vec<u8>>,
    /// The message signature, encoded in base64.  This field is omitted if the message is deleted.
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "as_opt_base64")]
    pub signature: Option<Vec<u8>>,
    /// Flag set to true if the message is deleted, and omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>
}

fn repad(data: &mut Option<Vec<u8>>, size: Option<usize>) {
    if let Some(size) = size {
        if data.is_some() && data.as_ref().unwrap().len() < size {
            data.as_mut().unwrap().resize(size, 0);
        }
    }
}

impl Message {
    pub fn from_row(row: &rusqlite::Row) -> Result<Message, rusqlite::Error> {
        let mut data: Option<Vec<u8>> = row.get(row.column_index("data")?)?;
        repad(&mut data, row.get::<_, Option<usize>>(row.column_index("data_size")?)?);
        let deleted = if data.is_none() { Some(true) } else { None };
        let session_id = match row.column_index("session_id") {
            Ok(index) => Some(row.get(index)?),
            Err(_) => None
        };
        return Ok(Message {
            id: row.get(row.column_index("id")?)?,
            session_id,
            timestamp: row.get(row.column_index("posted")?)?,
            edited: row.get(row.column_index("edited")?)?,
            updated: row.get(row.column_index("updated")?)?,
            data,
            signature: row.get(row.column_index("signature")?)?,
            deleted
        });
    }
}

fn bytes_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where D: Deserializer<'de> {
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|str| base64::decode(&str).map_err(|err| Error::custom(err.to_string())))
}

#[derive(Debug, Deserialize)]
pub struct PostMessage {
    #[serde(deserialize_with = "bytes_from_base64")]
    pub data: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_base64")]
    pub signature: Vec<u8>
}

#[derive(Debug, Serialize)]
pub struct DeletedMessage {
    #[serde(rename = "id")]
    pub updated: i64,
    pub deleted_message_id: i64
}

#[derive(Debug, Serialize)]
pub struct Room {
    #[serde(skip)]
    pub id: i64,
    #[serde(rename = "id")]
    pub token: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_file_id: Option<i64>,
    pub created: f64,
    pub updates: i64,
    pub default_read: bool,
    pub default_write: bool,
    pub default_upload: bool
}

impl Room {
    pub fn from_row(row: &rusqlite::Row) -> Result<Room, rusqlite::Error> {
        return Ok(Room {
            id: row.get(row.column_index("id")?)?,
            token: row.get(row.column_index("token")?)?,
            name: row.get(row.column_index("name")?)?,
            pinned_message_id: row.get(row.column_index("pinned")?)?,
            image_file_id: row.get(row.column_index("image")?)?,
            created: row.get(row.column_index("created")?)?,
            updates: row.get(row.column_index("updates")?)?,
            default_read: row.get(row.column_index("read")?)?,
            default_write: row.get(row.column_index("write")?)?,
            default_upload: row.get(row.column_index("upload")?)?
        });
    }
}



// FIXME: this appears to be used for both add/remove.  But what if we want to promote to admin, or
// demote to moderator?
#[derive(Debug, Deserialize)]
pub struct ChangeModeratorRequestBody {
    #[serde(rename = "room_id")]
    pub room_token: String,
    #[serde(rename = "public_key")]
    pub session_id: String,
    pub admin: Option<bool>
}

#[derive(Debug, Deserialize)]
pub struct PollRoomMetadata {
    /// Token of the room to poll
    pub room: String,
    /// The last `info_update` value the client has; results are only returned if the room has been
    /// modified since the value provided by the client.
    pub since_update: i64
}

#[derive(Debug, Serialize)]
pub struct RoomDetails {
    /// The token of this room
    pub token: String,
    /// Number of recently active users in the room
    pub active_users: i64,
    /// Metadata of the room; this omitted from the response when polling if the room metadata
    /// (other than active user count) has not changed since the request update counter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<RoomMetadata>
}

#[derive(Debug, Serialize)]
pub struct RoomMetadata {
    /// A counter that is updated whenever this room's metadata changes; clients are expected to
    /// poll for updates using this id.
    pub info_update: i64,
    /// Unix timestamp (seconds since epoch) when this room was created
    pub created: f64,
    /// The human-readable room name
    pub name: String,
    /// Text description of the room
    pub description: Option<String>,
    /// ID of an uploaded file that contains the image for this room
    pub image_id: Option<i64>,
    /// ID of a pinned message in this room
    pub pinned_id: Option<i64>,
    /// List of non-admin public moderator Session IDs.  This list includes both room-specific and
    /// global moderators, but not admins and only if the moderator is configured as visible.
    pub moderators: Vec<String>,
    /// List of public admin session IDs for this room.  In addition to everything moderators can
    /// do, admins can also add/remove/ban other moderators and admins.  As with `moderators` only
    /// visible admins are included.
    pub admins: Vec<String>,
    /// List of hidden moderator Session IDs.  This field is omitted if the requesting user is not
    /// a moderator or admin.
    pub hidden_mods: Option<Vec<String>>,
    /// List of hidden admin Session IDs.  This field is omitted if the requesting user is not a
    /// moderator or admin.
    pub hidden_admins: Option<Vec<String>>,
    /// Whether or not the requesting user has moderator powers.
    pub moderator: bool,
    /// Whether or not the requesting user has admin powers.
    pub admin: bool
}

#[derive(Debug, Deserialize)]
pub struct PollRoomMessages {
    /// Token of the room to poll for messages.
    pub room: String,
    /// Return new messages, edit, and deletions posted since this `updates` value.  Clients should
    /// poll with the most recent updates value they have received.
    pub since_update: i64
}

#[derive(Debug, Serialize)]
pub struct RoomMessages {
    /// The token of this room
    pub room: String,
    /// Vector of new/edited/deleted message posted to the room since the requested update.
    pub messages: Vec<Message>
}

#[derive(Debug, Deserialize)]
pub struct CompactPollRequestBody {
    #[serde(rename = "room_id")]
    pub room_token: String,

    // Deprecated: older Session clients pass the authorization token through this.  Newer clients
    // should use signed requests instead.
    pub auth_token: Option<String>,

    // Input parameters to query.  If these are omitted (or null) then this returns the latest 256
    // messages/deletions, in reverse order from what you get with regular polling.  New clients
    // should update to the new polling endpoints ASAP.
    pub from_message_server_id: Option<i64>,
    pub from_deletion_server_id: Option<i64>
}

#[derive(Debug, Serialize)]
pub struct CompactPollResponseBody {
    #[serde(rename = "room_id")]
    pub room_token: String,
    pub status_code: u16,
    pub deletions: Vec<DeletedMessage>,
    pub messages: Vec<OldMessage>,
    pub moderators: Vec<String>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub ciphertext: String,
    pub ephemeral_public_key: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusCode {
    pub status_code: u16
}
