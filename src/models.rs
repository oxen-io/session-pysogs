use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct Message {
    pub server_id: Option<i64>,
    pub text: String
}

impl Message {

    pub fn is_valid(&self) -> bool {
        return !self.text.is_empty();
    }
}
