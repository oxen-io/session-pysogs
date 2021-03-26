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
pub fn into_response(e: Rejection) -> Result<Response, Rejection> {
    if let Some(error) = e.find::<Error>() {
        match error {
            Error::DecryptionFailed | Error::InvalidOnionRequest | Error::InvalidRpcCall 
                | Error::NoSuchRoom | Error::ValidationFailed => return Ok(StatusCode::BAD_REQUEST.into_response()),
            Error::NoAuthToken => return Ok(StatusCode::UNAUTHORIZED.into_response()),
            Error::Unauthorized => return Ok(StatusCode::FORBIDDEN.into_response()),
            Error::DatabaseFailedInternally => {
                return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        };
    } else {
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
}
