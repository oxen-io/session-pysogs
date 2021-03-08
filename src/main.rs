use rusqlite::{params};
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};
use warp::Filter;

#[derive(Deserialize, Serialize, Debug)]
struct Message {
    text: String
}

#[tokio::main]
async fn main() {
    // Database
    let db_manager = SqliteConnectionManager::file("messages.db");
    let db_pool = r2d2::Pool::new(db_manager).unwrap();
    let db_conn = db_pool.get().unwrap();

    db_conn.execute(
        "CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            text TEXT
        )",
        params![]
    ).expect("Couldn't create messages table.");

    // POST /messages
    let send_message = warp::post()
        .and(warp::path("messages"))
        .and(warp::body::content_length_limit(1024 * 256)) // Limit body size to 256 kb
        .and(warp::body::json()) // Expect JSON
        .map(move |message: Message| {
            let db_conn = db_pool.get().unwrap(); // TODO: Fail gracefully

            db_conn.execute(
                "INSERT INTO messages (text) VALUES (?1)",
                params![message.text],
            ).expect("Couldn't insert message into database."); // TODO: Fail gracefully

            let mut stmt = db_conn.prepare("SELECT text FROM messages").unwrap();
            let mut messages_iter = stmt.query_map(params![], |row| {
                Ok(Message {
                    text: row.get(0).unwrap() // TODO: Fail gracefully
                })
            }).unwrap();

            for message in messages_iter {
                println!("message {:?}", message.unwrap());
            }

            warp::reply::json(&message)
        });

    warp::serve(send_message).run(([127, 0, 0, 1], 3030)).await;
}
