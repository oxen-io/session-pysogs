use serde::{Deserialize, Serialize, Serializer, Deserializer};
use base64;

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub id: i64,
    pub session_id: String,
    pub created: f64,
    pub last_active: f64,
    pub banned: bool,
    pub moderator: bool,
    pub admin: bool,
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
            admin: row.get(row.column_index("admin")?)?,
        });
    }
}

fn as_opt_base64<S>(val: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    s.serialize_str(&base64::encode(val.as_ref().unwrap()))
}

#[derive(Debug, Serialize)]
pub struct Message {
    #[serde(rename = "server_id")]
    pub id: i64,
    #[serde(rename = "room_id")]
    pub room: i64,
    #[serde(skip)]
    pub user: i64,
    #[serde(rename = "public_key", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub timestamp: i64, // unix epoch milliseconds; Deprecated in favour of `posted`
    pub posted: f64, // unix epoch seconds when the message was created
    pub edited: Option<f64>, // unix epoch seconds when the message was last edited (null if never edited)
    pub update: Option<i64>, // Set to the room's current `updates` value when created or last edited/deleted
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "as_opt_base64")]
    pub data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "as_opt_base64")]
    pub signature: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
}

fn bytes_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|str| base64::decode(&str).map_err(|err| Error::custom(err.to_string())))
}

#[derive(Debug, Deserialize)]
pub struct PostMessage {
    #[serde(deserialize_with = "bytes_from_base64")]
    pub data: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_base64")]
    pub signature: Vec<u8>,
}

impl Message {
    pub fn from_row(row: &rusqlite::Row) -> Result<Message, rusqlite::Error> {
        let posted: f64 = row.get(row.column_index("posted")?)?;
        let data: Option<Vec<u8>> = row.get(row.column_index("data")?)?;
        let session_id = match row.column_index("session_id") {
            Ok(index) => Some(row.get(index)?),
            Err(_) => None
        };
        let deleted = if data.is_none() { Some(true) } else { None };
        return Ok(Message {
            id: row.get(row.column_index("id")?)?,
            room: row.get(row.column_index("room")?)?,
            user: row.get(row.column_index("user")?)?,
            session_id,
            timestamp: (posted * 1000.0) as i64,
            posted,
            edited: row.get(row.column_index("edited")?)?,
            update: row.get(row.column_index("updated")?)?,
            data,
            signature: row.get(row.column_index("signature")?)?,
            deleted
        });
    }
}

#[derive(Debug, Serialize)]
pub struct DeletedMessage {
    #[serde(rename = "id")]
    pub updated: i64,
    pub deleted_message_id: i64,
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
    pub default_upload: bool,
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
            default_upload: row.get(row.column_index("upload")?)?,
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
pub struct CompactPollRequestBody {
    #[serde(rename = "room_id")]
    pub room_token: String,
    pub auth_token: Option<String>,
    // New querying ability, returns all new+edited+deleted messages since the given value
    pub since_update: Option<i64>,

    // Old querying:
    #[serde(rename = "from_deletion_server_id")]
    pub since_deletion: Option<i64>,
    #[serde(rename = "from_message_server_id")]
    pub since_message: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CompactPollResponseBody {
    #[serde(rename = "room_id")]
    pub room_token: String,
    pub status_code: u16,
    pub deletions: Option<Vec<DeletedMessage>>,
    pub messages: Vec<Message>,
    pub moderators: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub ciphertext: String,
    pub ephemeral_public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusCode {
    pub status_code: u16,
}
