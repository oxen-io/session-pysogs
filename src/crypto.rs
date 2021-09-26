use std::convert::TryInto;
use std::fs;
use std::sync::Mutex;

use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use hmac::{Hmac, Mac, NewMac};
use log::{error, warn};
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use sha2::Sha256;
use curve25519_dalek;
use blake2::{Blake2b, Digest};

use super::errors::Error;

type HmacSha256 = Hmac<Sha256>;

// By default the aes-gcm crate will use software implementations of both AES and the POLYVAL universal hash function. When
// targeting modern x86/x86_64 CPUs, use the following RUSTFLAGS to take advantage of high performance AES-NI and CLMUL CPU
// intrinsics:
//
// RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"

const IV_SIZE: usize = 12;

lazy_static::lazy_static! {

    pub static ref PRIVATE_KEY_PATH: Mutex<String> = Mutex::new("".to_string());

    pub static ref PRIVATE_KEY: x25519_dalek::StaticSecret = {
        let path: &str = &*PRIVATE_KEY_PATH.lock().unwrap();
        let raw_private_key = fs::read_to_string(path).unwrap();
        return curve25519_parser::parse_openssl_25519_privkey(raw_private_key.as_bytes()).unwrap();
    };

    pub static ref PUBLIC_KEY_PATH: Mutex<String> = Mutex::new("".to_string());

    pub static ref PUBLIC_KEY: x25519_dalek::PublicKey = {
        let path: &str = &*PUBLIC_KEY_PATH.lock().unwrap();
        let raw_public_key = fs::read_to_string(path).unwrap();
        return curve25519_parser::parse_openssl_25519_pubkey(raw_public_key.as_bytes()).unwrap();
    };

    // For backwards compatibility with token-using Session client versions we include a signature
    // in the "token" value we send back, signed using this key.  When we drop token support we can
    // also drop this.
    pub static ref TOKEN_SIGNING_KEYS: ed25519_dalek::Keypair = {
        let mut hasher = Blake2b::new();
        hasher.update(b"SOGS TOKEN SIGNING KEY");
        hasher.update(PRIVATE_KEY.to_bytes());
        hasher.update(PUBLIC_KEY.as_bytes());
        let res = hasher.finalize();
        let secret = ed25519_dalek::SecretKey::from_bytes(&res[0..32]).unwrap();
        let public = ed25519_dalek::PublicKey::from(&secret);
        ed25519_dalek::Keypair{ secret, public }
    };
}

/// Takes hex string representation of an ed25519 pubkey, returns the ed25519 pubkey, derived x25519 pubkey, and the Session id in hex.
pub fn get_pubkeys(edpk_hex: &str) -> Result<(ed25519_dalek::PublicKey, x25519_dalek::PublicKey, String), warp::reject::Rejection> {
    if edpk_hex.len() != 64 {
        return Err(warp::reject::custom(Error::DecryptionFailed));
    }
    let edpk_bytes = match hex::decode(edpk_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            warn!("Invalid ed25519 pubkey: '{}' is not hex", edpk_hex);
            return Err(warp::reject::custom(Error::DecryptionFailed));
        }
    };

    let edpk = ed25519_dalek::PublicKey::from_bytes(&edpk_bytes).map_err(|_| Error::DecryptionFailed)?;
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&edpk_bytes);
    let edpoint = compressed.decompress().ok_or(warp::reject::custom(Error::DecryptionFailed))?;
    if !edpoint.is_torsion_free() {
        return Err(Error::DecryptionFailed.into());
    }

    let xpk = x25519_dalek::PublicKey::from(*edpoint.to_montgomery().as_bytes());
    let mut session_id = String::with_capacity(66);
    session_id.push_str("05");
    session_id.push_str(&hex::encode(xpk.as_bytes()));
    return Ok((edpk, xpk, session_id));
}

pub fn get_x25519_symmetric_key(
    public_key: &[u8], private_key: &x25519_dalek::StaticSecret,
) -> Result<Vec<u8>, warp::reject::Rejection> {
    if public_key.len() != 32 {
        error!(
            "Couldn't create symmetric key using public key of invalid length: {}.",
            hex::encode(public_key)
        );
        return Err(warp::reject::custom(Error::DecryptionFailed));
    }
    let public_key: [u8; 32] = public_key.try_into().unwrap(); // Safe because we know it has a length of 32 at this point
    let dalek_public_key = x25519_dalek::PublicKey::from(public_key);
    let shared_secret = private_key.diffie_hellman(&dalek_public_key).to_bytes();
    let mut mac = HmacSha256::new_varkey(b"LOKI").unwrap();
    mac.update(&shared_secret);
    return Ok(mac.finalize().into_bytes().to_vec());
}

pub fn encrypt_aes_gcm(
    plaintext: &[u8], symmetric_key: &[u8],
) -> Result<Vec<u8>, warp::reject::Rejection> {
    let mut iv = [0u8; IV_SIZE];
    thread_rng().fill(&mut iv[..]);
    let cipher = Aes256Gcm::new(&GenericArray::from_slice(symmetric_key));
    match cipher.encrypt(GenericArray::from_slice(&iv), plaintext) {
        Ok(mut ciphertext) => {
            let mut iv_and_ciphertext = iv.to_vec();
            iv_and_ciphertext.append(&mut ciphertext);
            return Ok(iv_and_ciphertext);
        }
        Err(e) => {
            error!("Couldn't encrypt ciphertext: {}.", e);
            return Err(warp::reject::custom(Error::DecryptionFailed));
        }
    };
}

pub fn decrypt_aes_gcm(
    iv_and_ciphertext: &[u8], symmetric_key: &[u8],
) -> Result<Vec<u8>, warp::reject::Rejection> {
    if iv_and_ciphertext.len() < IV_SIZE {
        warn!("Ignoring ciphertext of invalid size: {}.", iv_and_ciphertext.len());
        return Err(warp::reject::custom(Error::DecryptionFailed));
    }
    let iv: [u8; IV_SIZE] = iv_and_ciphertext[0..IV_SIZE].try_into().unwrap(); // Safe because we know iv_and_ciphertext has a length of at least IV_SIZE bytes
    let ciphertext: Vec<u8> = iv_and_ciphertext[IV_SIZE..].try_into().unwrap(); // Safe because we know iv_and_ciphertext has a length of at least IV_SIZE bytes
    let cipher = Aes256Gcm::new(&GenericArray::from_slice(symmetric_key));
    match cipher.decrypt(GenericArray::from_slice(&iv), &*ciphertext) {
        Ok(plaintext) => return Ok(plaintext),
        Err(e) => {
            error!("Couldn't decrypt ciphertext: {}.", e);
            return Err(warp::reject::custom(Error::DecryptionFailed));
        }
    };
}

pub fn generate_x25519_key_pair() -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey) {
    let private_key = x25519_dalek::StaticSecret::new(OsRng);
    let public_key = x25519_dalek::PublicKey::from(&private_key);
    return (private_key, public_key);
}
