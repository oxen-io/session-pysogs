use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    DatabaseFailedInternally,
    InvalidOnionRequest,
    /// Usually this means the endpoint or HTTP method specified in the RPC call was malformed.
    InvalidRpcCall,
    NoSuchRoom,
    Unauthorized,
    ValidationFailed,
}
impl warp::reject::Reject for Error {}

#[rustfmt::skip]
pub fn into_response(e: Rejection) -> Result<Response, Rejection> {
    if let Some(error) = e.find::<Error>() {
        match error {
            Error::DecryptionFailed | Error::InvalidOnionRequest | Error::InvalidRpcCall 
                | Error::NoSuchRoom | Error::ValidationFailed => return Ok(StatusCode::BAD_REQUEST.into_response()),
            Error::Unauthorized => return Ok(StatusCode::FORBIDDEN.into_response()),
            Error::DatabaseFailedInternally => {
                return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        };
    } else {
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
}
