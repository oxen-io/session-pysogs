use rusqlite::{params};
use r2d2_sqlite::SqliteConnectionManager;
use warp::Filter;

#[tokio::main]
async fn main() {
    // Database
    let db_manager = SqliteConnectionManager::file("messages.db");
    let db_pool = r2d2::Pool::new(db_manager).unwrap();
    let db_conn = db_pool.get().unwrap();

    db_conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            text TEXT
        )",
        params![]
    ).expect("Couldn't create messages table.");

    // Routes
    let get_messages = routes::get_messages(db_pool.clone());
    let send_message = routes::send_message(db_pool.clone());
    let routes = get_messages.or(send_message);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

mod routes {
    use r2d2_sqlite::SqliteConnectionManager;
    use warp::Filter;

    use super::handlers;

    /// POST /messages
    pub fn send_message(
        db_pool: r2d2::Pool<SqliteConnectionManager>,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::post()
            .and(warp::path("messages"))
            .and(warp::body::content_length_limit(1024 * 256)) // Limit body size to 256 kb
            .and(warp::body::json()) // Expect JSON
            .and(warp::any().map(move || db_pool.clone()))
            .and_then(handlers::insert_message)
    }

    /// GET /messages
    /// 
    /// Returns the last `count` messages.
    pub fn get_messages(
        db_pool: r2d2::Pool<SqliteConnectionManager>,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        // TODO: Count
        warp::get()
            .and(warp::path("messages"))
            .and(warp::any().map(move || db_pool.clone()))
            .and_then(handlers::get_messages)
    }
}

mod handlers {
    use std::convert::Infallible;

    use rusqlite::{params};
    use r2d2_sqlite::SqliteConnectionManager;
    use warp::http::StatusCode;

    use super::models::Message;

    /// Inserts the given `message` into the database.
    pub async fn insert_message(message: Message, db_pool: r2d2::Pool<SqliteConnectionManager>) -> Result<impl warp::Reply, Infallible> {
        let db_conn = db_pool.get().unwrap(); // TODO: Fail gracefully
        db_conn.execute(
            "INSERT INTO messages (text) VALUES (?1)",
            params![message.text],
        ).expect("Couldn't insert message into database."); // TODO: Fail gracefully
        Ok(StatusCode::CREATED)
    }

    /// Returns the last `count` messages from the database.
    pub async fn get_messages(db_pool: r2d2::Pool<SqliteConnectionManager>) -> Result<impl warp::Reply, Infallible> {
        // TODO: Count
        let db_conn = db_pool.get().unwrap(); // TODO: Fail gracefully
        // TODO: Implement

        let mut stmt = db_conn.prepare("SELECT text FROM messages").unwrap(); // TODO: Fail gracefully
        let messages: Result<Vec<Message>, rusqlite::Error> = stmt.query_map(params![], |row| {
            Ok(Message {
                text: row.get(0).unwrap() // TODO: Fail gracefully
            })
        }).unwrap().into_iter().collect(); // TODO: Fail gracefully

        Ok(warp::reply::json(&messages.unwrap()))
    }
}

mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Message {
        pub text: String
    }
}