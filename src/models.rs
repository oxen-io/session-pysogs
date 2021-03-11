use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct ValidationError;
impl warp::reject::Reject for ValidationError { }

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
