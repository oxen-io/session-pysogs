use std::convert::TryInto;

use regex::Regex;
use serde::{Deserialize, Serialize};
use warp::Rejection;

use super::crypto;
use super::rpc;
use super::storage;

#[derive(Deserialize, Serialize, Debug)]
struct LsrpcPayload {
    pub ciphertext: Vec<u8>,
    pub metadata: LsrpcPayloadMetadata
}

#[derive(Deserialize, Serialize, Debug)]
struct LsrpcPayloadMetadata {
    pub ephemeral_key: String
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RpcCall {
    pub endpoint: String,
    pub body: String,
    pub method: String
}

#[derive(Debug)]
pub struct RequestSizeExceededError;
impl warp::reject::Reject for RequestSizeExceededError { }

#[derive(Debug)]
pub struct ParsingError;
impl warp::reject::Reject for ParsingError { }

pub async fn handle_lsrpc_request(blob: warp::hyper::body::Bytes, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    if blob.len() > 10 * 1024 * 1024 { // Match storage server
        return Err(warp::reject::custom(RequestSizeExceededError));
    }
    let payload = parse_lsrpc_payload(blob).await?;
    let plaintext = decrypt_lsrpc_payload(payload).await?;
    let json = match String::from_utf8(plaintext) {
        Ok(json) => json,
        Err(e) => {
            println!("Couldn't parse RPC call from JSON due to error: {:?}.", e);
            return Err(warp::reject::custom(ParsingError));
        }
    };
    let rpc_call = match serde_json::from_str(&json) {
        Ok(rpc_call) => rpc_call,
        Err(e) => {
            println!("Couldn't parse RPC call from JSON due to error: {:?}.", e);
            return Err(warp::reject::custom(ParsingError));
        }
    };
    return rpc::handle_rpc_call(rpc_call, &pool).await;
}

async fn parse_lsrpc_payload(blob: warp::hyper::body::Bytes) -> Result<LsrpcPayload, Rejection> {
    // The encoding of onion requests looks like: | 4 bytes: size N of ciphertext | N bytes: ciphertext | json as utf8 |
    if blob.len() < 4 { 
        println!("Ignoring blob of invalid size.");
        return Err(warp::reject::custom(ParsingError)); 
    }
    // Extract the different components
    // This is safe because we know blob has a length of at least 4 bytes
    let size = as_le_u32(&blob[0..4].try_into().unwrap()) as usize;
    let ciphertext: Vec<u8> = blob[4..(4 + size)].try_into().unwrap();
    let utf8_json: Vec<u8> = blob[(4 + size)..].try_into().unwrap();
    // Parse JSON
    let json = match String::from_utf8(utf8_json) {
        Ok(json) => json,
        Err(e) => {
            println!("Couldn't parse string from bytes due to error: {:?}.", e);
            return Err(warp::reject::custom(ParsingError));
        }
    };
    // Parse metadata
    let metadata: LsrpcPayloadMetadata = match serde_json::from_str(&json) {
        Ok(metadata) => metadata,
        Err(e) => {
            println!("Couldn't parse LSRPC payload metadata due to error: {:?}.", e);
            return Err(warp::reject::custom(ParsingError));
        }
    };
    // Check that the ephemeral public key is valid hex
    let re = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
    if !re.is_match(&metadata.ephemeral_key) { 
        println!("Ignoring non hex encoded LSRPC payload ephemeral key.");
        return Err(warp::reject::custom(ParsingError)); 
    };
    // Return
    return Ok(LsrpcPayload { ciphertext : ciphertext, metadata : metadata });
}

async fn decrypt_lsrpc_payload(payload: LsrpcPayload) -> Result<Vec<u8>, Rejection> {
    let ephemeral_key = hex::decode(payload.metadata.ephemeral_key).unwrap(); // Safe because it was validated in the parsing step
    let symmetric_key = crypto::get_x25519_symmetric_key(ephemeral_key, get_private_key()).await?;
    let plaintext = crypto::decrypt_aes_gcm(payload.ciphertext, symmetric_key).await?;
    return Ok(plaintext);
}

// Utilities

// FIXME: get_private_key() and get_public_key() should be lazy static variables

fn get_private_key() -> x25519_dalek::StaticSecret {
    let bytes = include_bytes!("../x25519_private_key.pem");
    return curve25519_parser::parse_openssl_25519_privkey(bytes).unwrap();
}

pub fn get_public_key() -> x25519_dalek::PublicKey {
    let bytes = include_bytes!("../x25519_public_key.pem");
    return curve25519_parser::parse_openssl_25519_pubkey(bytes).unwrap();
}

fn as_le_u32(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 00) +
    ((array[1] as u32) << 08) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}