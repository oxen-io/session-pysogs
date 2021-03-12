
#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    DatabaseFailedInternally,
    InvalidRequest,
    ParsingFailed,
    Unauthorized,
    ValidationFailed
}
impl warp::reject::Reject for Error { }
