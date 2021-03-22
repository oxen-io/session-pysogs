use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Message {
    pub server_id: Option<i64>,
    pub data: String,
    pub signature: String
}

impl Message {

    pub fn is_valid(&self) -> bool {
        return !self.data.is_empty();
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub ciphertext: String,
    pub ephemeral_public_key: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenericResponse { 
    pub result: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusCode {
    pub status_code: u16
}
