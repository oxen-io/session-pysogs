
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
