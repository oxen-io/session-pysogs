
#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    DatabaseFailedInternally,
    /// No valid request could be formed. Usually this means the endpoint or 
    /// HTTP method specified in the RPC call was malformed.
    InvalidRequest,
    /// Couldn't parse LSRPC request to a valid RPC call.
    ParsingFailed,
    Unauthorized,
    /// The provided data is invalid.
    ValidationFailed
}
impl warp::reject::Reject for Error { }
