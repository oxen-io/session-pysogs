use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply::Reply, reply::Response, Rejection};

use super::crypto;
use super::errors::Error;
use super::models;
use super::rpc;

#[derive(Deserialize, Serialize, Debug)]
struct OnionRequestPayload {
    pub ciphertext: Vec<u8>,
    pub metadata: OnionRequestPayloadMetadata
}

#[derive(Deserialize, Serialize, Debug)]
struct OnionRequestPayloadMetadata {
    pub ephemeral_key: String
}

pub async fn handle_onion_request(blob: warp::hyper::body::Bytes) -> Result<Response, Rejection> {
    let payload = parse_onion_request_payload(blob).await?;
    let (plaintext, symmetric_key) = decrypt_onion_request_payload(payload).await?;
    // From this point on we can wrap any error that occurs in a HTTP response that's
    // encrypted with the given symmetric key, so that the error that occurred is
    // propagated back to the client that made the onion request.
    //
    // If an error occurred before this point we'll have responded to the Service Node
    // with a unsuccessful status code, which it'll have propagated back to the client
    // as a "Loki server error" (i.e. the actual error is hidden from the client that
    // made the onion request). This is unfortunate but cannot be solved without
    // fundamentally changing how onion requests work.
    return handle_decrypted_onion_request(&plaintext, &symmetric_key).await;
}

async fn handle_decrypted_onion_request(
    plaintext: &[u8], symmetric_key: &[u8]
) -> Result<Response, Rejection> {
    let rpc_call = match serde_json::from_slice(plaintext) {
        Ok(rpc_call) => rpc_call,
        Err(e) => {
            println!("Couldn't parse RPC call from JSON due to error: {}.", e);
            return Err(warp::reject::custom(Error::InvalidOnionRequest));
        }
    };
    // Perform the RPC call
    let result = rpc::handle_rpc_call(rpc_call)
        .await
        // Turn any error that occurred into an HTTP response
        .or_else(super::errors::into_response)?; // Safe because at this point any error should be caught and turned into an HTTP response (i.e. an OK result)
                                                 // Encrypt the HTTP response so that it's propagated back to the client that made
                                                 // the onion request
    return encrypt_response(result, symmetric_key).await;
}

async fn parse_onion_request_payload(
    blob: warp::hyper::body::Bytes
) -> Result<OnionRequestPayload, Rejection> {
    // The encoding of an onion request looks like: | 4 bytes: size N of ciphertext | N bytes: ciphertext | json as utf8 |
    if blob.len() < 4 {
        println!("Ignoring blob of invalid size.");
        return Err(warp::reject::custom(Error::InvalidOnionRequest));
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
            println!("Couldn't parse onion request payload metadata due to error: {}.", e);
            return Err(warp::reject::custom(Error::InvalidOnionRequest));
        }
    };
    // Parse metadata
    let metadata: OnionRequestPayloadMetadata = match serde_json::from_str(&json) {
        Ok(metadata) => metadata,
        Err(e) => {
            println!("Couldn't parse onion request payload metadata due to error: {}.", e);
            return Err(warp::reject::custom(Error::InvalidOnionRequest));
        }
    };
    // Check that the ephemeral public key is valid hex
    if hex::decode(&metadata.ephemeral_key).is_err() {
        println!("Ignoring non hex encoded onion request payload ephemeral key.");
        return Err(warp::reject::custom(Error::InvalidOnionRequest));
    };
    // Return
    return Ok(OnionRequestPayload { ciphertext, metadata });
}

/// Returns the decrypted `payload.ciphertext` plus the `symmetric_key` that was used for decryption if successful.
async fn decrypt_onion_request_payload(
    payload: OnionRequestPayload
) -> Result<(Vec<u8>, Vec<u8>), Rejection> {
    let ephemeral_key = hex::decode(payload.metadata.ephemeral_key).unwrap(); // Safe because it was validated in the parsing step
    let symmetric_key =
        crypto::get_x25519_symmetric_key(&ephemeral_key, &crypto::PRIVATE_KEY).await?;
    let plaintext = crypto::decrypt_aes_gcm(&payload.ciphertext, &symmetric_key).await?;
    return Ok((plaintext, symmetric_key));
}

async fn encrypt_response(response: Response, symmetric_key: &[u8]) -> Result<Response, Rejection> {
    let bytes: Vec<u8>;
    if response.status().is_success() {
        let (_, body) = response.into_parts();
        bytes = warp::hyper::body::to_bytes(body).await.unwrap().to_vec();
    } else {
        let error = models::StatusCode { status_code: response.status().as_u16() };
        bytes = serde_json::to_vec(&error).unwrap();
    }
    let ciphertext = crypto::encrypt_aes_gcm(&bytes, symmetric_key).await.unwrap();
    let json = base64::encode(&ciphertext);
    let response =
        warp::http::Response::builder().status(StatusCode::OK.as_u16()).body(json).into_response();
    return Ok(response);
}

// Utilities

fn as_le_u32(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 00)
        + ((array[1] as u32) << 08)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}
