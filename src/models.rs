use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct ValidationError;
impl warp::reject::Reject for ValidationError { }

#[derive(Deserialize, Serialize, Debug)]
pub struct Message {
    pub text: String
}

impl Message {

    pub fn is_valid(&self) -> bool {
        return !self.text.is_empty();
    }
}

#[derive(Debug, Deserialize)]
pub struct QueryOptions {
    pub limit: Option<u16>,
    pub from_server_id: Option<i64>
}