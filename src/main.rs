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
    use super::models::QueryOptions;

    type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

    /// POST /messages
    pub fn send_message(
        db_pool: DatabaseConnectionPool,
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
        db_pool: DatabaseConnectionPool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::get()
            .and(warp::path("messages"))
            .and(warp::query::<QueryOptions>())
            .and(warp::any().map(move || db_pool.clone()))
            .and_then(handlers::get_messages)
    }
}

mod handlers {
    use log;
    use rusqlite::params;
    use r2d2_sqlite::SqliteConnectionManager;
    use warp::http::StatusCode;

    use super::models::Message;
    use super::models::QueryOptions;

    type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
    type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

    #[derive(Debug)]
    struct DatabaseError;
    impl warp::reject::Reject for DatabaseError { }

    /// Inserts the given `message` into the database.
    pub async fn insert_message(message: Message, db_pool: DatabaseConnectionPool) -> Result<impl warp::Reply, warp::reject::Rejection> {
        // TODO: Validation
        // Get a database connection
        let db_conn = get_db_conn(db_pool)?;
        // Insert the message
        db_conn.execute(
            "INSERT INTO messages (text) VALUES (?1)",
            params![message.text],
        ).expect("Couldn't insert message into database."); // TODO: Fail gracefully
        // Return
        Ok(StatusCode::CREATED)
    }

    /// Returns the last `options.limit` messages from the database.
    pub async fn get_messages(options: QueryOptions, db_pool: DatabaseConnectionPool) -> Result<impl warp::Reply, warp::reject::Rejection> {
        // Get a database connection
        let db_conn = get_db_conn(db_pool)?;
        // Query the database
        let raw_query = "SELECT text FROM messages";
        let mut query = get_db_query(&raw_query, db_conn)?;
        let messages: Result<Vec<Message>, rusqlite::Error> = query.query_map(params![], |row| {
            Ok(Message {
                text: row.get(0).unwrap() // TODO: Fail gracefully
            })
        }).unwrap().into_iter().take(options.limit.unwrap_or(std::u16::MAX).into()).collect(); // TODO: Fail gracefully
        // Return the messages
        Ok(warp::reply::json(&messages.unwrap())) // TODO: Fail gracefully
    }

    fn get_db_conn(db_pool: DatabaseConnectionPool) -> Result<DatabaseConnection, warp::reject::Rejection> {
        match db_pool.get() {
            Ok(db_conn) => return Ok(db_conn),
            Err(e) => { 
                log::warn!("Couldn't get database connection from pool due to error: {:?}.", e);
                return Err(warp::reject::custom(DatabaseError)) 
            }
        }
    }

    fn get_db_query(raw_query: &str, db_conn: DatabaseConnection) -> Result<rusqlite::Statement, warp::reject::Rejection> {
        match db_conn.prepare(raw_query) {
            Ok(query) => return Ok(query),
            Err(e) => { 
                log::warn!("Couldn't create database query due to error: {:?}.", e);
                return Err(warp::reject::custom(DatabaseError)) 
            }
        };
    }
}

mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Message {
        pub text: String
    }

    #[derive(Debug, Deserialize)]
    pub struct QueryOptions {
        pub limit: Option<u16>
    }
}