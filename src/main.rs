use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use warp::Filter;

#[derive(Deserialize, Serialize, Debug)]
struct Message {
    text: String
}

#[tokio::main]
async fn main() {
    // Database
    // TODO: Database file
    let db_conn = Connection::open_in_memory().expect("Couldn't open database connection.");

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
        .map(|message: Message| {
            // TODO: Don't share database connection across threads
            let db_conn = Connection::open_in_memory().expect("Couldn't open database connection.");

            db_conn.execute(
                "INSERT INTO messages (text) VALUES (?1)",
                params![message.text],
            ).expect("Couldn't insert message into database."); // TODO: Fail gracefully

            // let mut stmt = db_conn.prepare("SELECT text FROM messages");
            // let messages_iter = stmt.query_map([], |row| {
            //     Ok(Message {
            //         text: row.get(0)?
            //     })
            // })?;

            // for message in messages_iter {
            //     println!("message {:?}", message.unwrap());
            // }

            warp::reply::json(&message)
        });

    warp::serve(send_message).run(([127, 0, 0, 1], 3030)).await;
}
