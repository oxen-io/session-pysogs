use std::convert::TryInto;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};

#[derive(Debug)]
pub struct DecryptionError;
impl warp::reject::Reject for DecryptionError { }

// By default the aes-gcm crate will use software implementations of both AES and the POLYVAL universal hash function. When 
// targeting modern x86/x86_64 CPUs, use the following RUSTFLAGS to take advantage of high performance AES-NI and CLMUL CPU
// intrinsics:
// RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"

const IV_SIZE: usize = 12;

pub fn decrypt_aes_gcm(iv_and_ciphertext: Vec<u8>, symmetric_key: Vec<u8>) -> Result<Vec<u8>, warp::reject::Rejection> {
    if iv_and_ciphertext.len() < IV_SIZE { 
        println!("Ignoring ciphertext of invalid size.");
        return Err(warp::reject::custom(DecryptionError)); 
    }
    let iv: Vec<u8> = iv_and_ciphertext[0..IV_SIZE].try_into().unwrap();
    let ciphertext: Vec<u8> = iv_and_ciphertext[IV_SIZE..].try_into().unwrap();
    let cipher = Aes256Gcm::new(&GenericArray::from_slice(&symmetric_key));
    match cipher.decrypt(GenericArray::from_slice(&iv), &*ciphertext) {
        Ok(plaintext) => return Ok(plaintext),
        Err(e) => {
            println!("Couldn't decrypt ciphertext due to error: {:?}.", e);
            return Err(warp::reject::custom(DecryptionError));
        }
    }
}
