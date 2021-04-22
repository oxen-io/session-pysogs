use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    DatabaseFailedInternally,
    InvalidOnionRequest,
    /// Usually this means the endpoint or HTTP method specified in the RPC call was malformed.
    InvalidRpcCall,
    /// The requesting user didn't provide an auth token for a route that requires one.
    NoAuthToken,
    NoSuchRoom,
    /// The requesting user provided a valid auth token, but they don't have a high enough permission level.
    Unauthorized,
    ValidationFailed,
}
impl warp::reject::Reject for Error {}

#[rustfmt::skip]
pub fn status_code(e: Rejection) -> StatusCode {
    if let Some(error) = e.find::<Error>() {
        match error {
            Error::DecryptionFailed | Error::InvalidOnionRequest | Error::InvalidRpcCall 
                | Error::NoSuchRoom | Error::ValidationFailed => return StatusCode::BAD_REQUEST,
            Error::NoAuthToken => return StatusCode::UNAUTHORIZED,
            Error::Unauthorized => return StatusCode::FORBIDDEN,
            Error::DatabaseFailedInternally => return StatusCode::INTERNAL_SERVER_ERROR
        };
    } else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
}

pub fn into_response(e: Rejection) -> Result<Response, Rejection> {
    return Ok(status_code(e).into_response());
}
