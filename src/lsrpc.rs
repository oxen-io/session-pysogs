use std::convert::TryInto;

use regex::Regex;
use serde::{Deserialize, Serialize};
use warp::Rejection;

use super::crypto;
use super::storage;

#[derive(Deserialize, Serialize, Debug)]
struct LSRPCPayload {
    pub ciphertext: Vec<u8>,
    pub metadata: LSRPCPayloadMetadata
}

#[derive(Deserialize, Serialize, Debug)]
struct LSRPCPayloadMetadata {
    pub ephemeral_key: String
}

#[derive(Debug)]
pub struct ParsingError;
impl warp::reject::Reject for ParsingError { }

pub async fn handle_lsrpc_request(blob: warp::hyper::body::Bytes, pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
    let payload = parse_lsrpc_request(blob)?;
    let plaintext = decrypt_lsrpc_request(payload)?;
    println!("{}", String::from_utf8(plaintext).unwrap());
    return Ok(warp::reply::reply());
}

fn parse_lsrpc_request(blob: warp::hyper::body::Bytes) -> Result<LSRPCPayload, Rejection> {
    // The encoding of onion requests looks like: | 4 bytes: size N of ciphertext | N bytes: ciphertext | json as utf8 |
    if blob.len() < 4 { 
        println!("Ignoring blob of invalid size.");
        return Err(warp::reject::custom(ParsingError)); 
    }
    // Extract the different components
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
    let metadata: LSRPCPayloadMetadata = match serde_json::from_str(&json) {
        Ok(metadata) => metadata,
        Err(e) => {
            println!("Couldn't parse LSRPC request metadata due to error: {:?}.", e);
            return Err(warp::reject::custom(ParsingError));
        }
    };
    // Check that the ephemeral public key is valid hex
    let re = Regex::new(r"^[0-9a-fA-F]+$").unwrap(); // Force
    if !re.is_match(&metadata.ephemeral_key) { 
        println!("Ignoring non hex encoded LSRPC request ephemeral key.");
        return Err(warp::reject::custom(ParsingError)); 
    };
    // Return
    return Ok(LSRPCPayload { ciphertext : ciphertext, metadata : metadata });
}

fn decrypt_lsrpc_request(payload: LSRPCPayload) -> Result<Vec<u8>, Rejection> {
    let public_key = hex::decode(payload.metadata.ephemeral_key).unwrap(); // Safe because it was validated in the parsing step
    let symmetric_key = crypto::get_x25519_symmetric_key(public_key, get_private_key())?;
    let plaintext = crypto::decrypt_aes_gcm(payload.ciphertext, symmetric_key)?;
    return Ok(plaintext);
}

// Utilities

// FIXME: get_private_key() should be a lazy static variable

fn get_private_key() -> Vec<u8> {
    let raw = std::fs::read_to_string("x25519_private_key.pem").unwrap();
    return pem::parse(raw).unwrap().contents;
}

fn as_le_u32(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 00) +
    ((array[1] as u32) << 08) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}