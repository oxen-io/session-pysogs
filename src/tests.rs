use std::collections::HashMap;
use std::fs;
use std::path::Path;

use rand::{thread_rng, Rng};
use rusqlite::params;
use warp::http::StatusCode;

use super::crypto;
use super::handlers;
use super::models;
use super::storage;

macro_rules! aw {
    ($e:expr) => {
        tokio_test::block_on($e)
    };
}

fn perform_main_setup() {
    storage::create_main_database_if_needed();
    fs::create_dir_all("rooms").unwrap();
    fs::create_dir_all("files").unwrap();
}

fn set_up_test_room() {
    perform_main_setup();
    let test_room_id = "test_room";
    let test_room_name = "Test Room";
    let test_room = models::Room { id: test_room_id.to_string(), name: test_room_name.to_string() };
    aw!(handlers::create_room(test_room)).unwrap();
    let raw_path = format!("rooms/{}.db", test_room_id);
    let path = Path::new(&raw_path);
    fs::read(path).unwrap(); // Fail if this doesn't exist
}

fn get_auth_token() -> (String, String) {
    // Get a database connection pool
    let test_room_id = "test_room";
    let pool = storage::pool_by_room_id(&test_room_id);
    // Generate a fake user key pair
    let (user_private_key, user_public_key) = crypto::generate_x25519_key_pair();
    let hex_user_public_key = format!("05{}", hex::encode(user_public_key.to_bytes()));
    // Get a challenge
    let mut query_params: HashMap<String, String> = HashMap::new();
    query_params.insert("public_key".to_string(), hex_user_public_key.clone());
    let challenge = handlers::get_auth_token_challenge(query_params, &pool).unwrap();
    // Generate a symmetric key
    let ephemeral_public_key = base64::decode(challenge.ephemeral_public_key).unwrap();
    let symmetric_key =
        crypto::get_x25519_symmetric_key(&ephemeral_public_key, &user_private_key).unwrap();
    // Decrypt the challenge
    let ciphertext = base64::decode(challenge.ciphertext).unwrap();
    let plaintext = crypto::decrypt_aes_gcm(&ciphertext, &symmetric_key).unwrap();
    let auth_token = hex::encode(plaintext);
    // Try to claim the token
    let response = handlers::claim_auth_token(&hex_user_public_key, &auth_token, &pool).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // return
    return (auth_token, hex_user_public_key);
}

#[test]
fn test_authorization() {
    // Ensure the test room is set up and get a database connection pool
    set_up_test_room();
    let test_room_id = "test_room";
    let pool = storage::pool_by_room_id(&test_room_id);
    // Get an auth token
    let (_, hex_user_public_key) = get_auth_token(); // This tests claiming a token internally
                                                     // Try to claim an incorrect token
    let mut incorrect_token = [0u8; 48];
    thread_rng().fill(&mut incorrect_token[..]);
    let hex_incorrect_token = hex::encode(incorrect_token);
    match handlers::claim_auth_token(&hex_user_public_key, &hex_incorrect_token, &pool) {
        Ok(_) => assert!(false),
        Err(_) => (),
    }
}

#[test]
fn test_file_handling() {
    // Ensure the test room is set up and get a database connection pool
    set_up_test_room();
    let test_room_id = "test_room";
    let pool = storage::pool_by_room_id(&test_room_id);
    // Get an auth token
    let (auth_token, _) = get_auth_token();
    // Store the test file
    aw!(handlers::store_file(TEST_FILE, &auth_token, &pool)).unwrap();
    // Check that there's a file record
    let conn = pool.get().unwrap();
    let raw_query = format!("SELECT id FROM {}", storage::FILES_TABLE);
    let id: i64 = conn.query_row(&raw_query, params![], |row| Ok(row.get(0)?)).unwrap();
    // Retrieve the file and check the content
    let base64_encoded_file = aw!(handlers::get_file(id, &auth_token, &pool)).unwrap().result;
    assert_eq!(base64_encoded_file, TEST_FILE);
    // Prune the file and check that it's gone
    aw!(storage::prune_files(-60)); // Will evaluate to now + 60
    match fs::read(format!("files/{}", id)) {
        Ok(_) => assert!(false), // It should be gone now
        Err(_) => (),
    }
    // Check that the file record is also gone
    let conn = pool.get().unwrap();
    let raw_query = format!("SELECT id FROM {}", storage::FILES_TABLE);
    let result: Result<String, _> = conn.query_row(&raw_query, params![], |row| Ok(row.get(0)?));
    match result {
        Ok(_) => assert!(false), // It should be gone now
        Err(_) => (),
    }
}

const TEST_FILE: &str = "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";
