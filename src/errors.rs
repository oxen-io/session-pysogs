use warp::{http::StatusCode, Rejection, reply::Reply, reply::Response};

#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    DatabaseFailedInternally,
    InvalidOnionRequest,
    /// Usually this means the endpoint or HTTP method specified in the RPC call was malformed.
    InvalidRpcCall,
    Unauthorized,
    ValidationFailed
}
impl warp::reject::Reject for Error { }

pub fn into_response(e: Rejection) -> Result<Response, Rejection> {
    if let Some(error) = e.find::<Error>() {
        match error {
            Error::DecryptionFailed | Error::InvalidOnionRequest | Error::InvalidRpcCall
                | Error::ValidationFailed => return Ok(StatusCode::BAD_REQUEST.into_response()),
            Error::Unauthorized => return Ok(StatusCode::FORBIDDEN.into_response()),
            Error::DatabaseFailedInternally => return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        };
    } else {
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
}
