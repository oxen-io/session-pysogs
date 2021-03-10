use rusqlite::{params};
use warp::Filter;

#[tokio::main]
async fn main() {
    // Database
    let db_pool = storage::get_db_pool();
    let db_conn = storage::get_db_conn(&db_pool).unwrap(); // Force

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
    use warp::{Filter, Rejection};

    use super::handlers;
    use super::models;
    use super::storage;

    /// POST /messages
    pub fn send_message(
        db_pool: storage::DatabaseConnectionPool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
        return warp::post()
            .and(warp::path("messages"))
            .and(warp::body::content_length_limit(1024 * 256)) // Limit body size to 256 kb
            .and(warp::body::json()) // Expect JSON
            .and(warp::any().map(move || db_pool.clone()))
            .and_then(handlers::insert_message)
            .recover(handle_error);
    }

    /// GET /messages
    /// 
    /// Returns the last `count` messages.
    pub fn get_messages(
        db_pool: storage::DatabaseConnectionPool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
        return warp::get()
            .and(warp::path("messages"))
            .and(warp::query::<models::QueryOptions>())
            .and(warp::any().map(move || db_pool.clone()))
            .and_then(handlers::get_messages)
            .recover(handle_error);
    }

    async fn handle_error(e: Rejection) -> Result<impl warp::Reply, Rejection> {
        let reply = warp::reply::reply();
        if let Some(models::ValidationError) = e.find() {
            return Ok(warp::reply::with_status(reply, warp::http::StatusCode::BAD_REQUEST));
        } else if let Some(storage::DatabaseError) = e.find() {
            return Ok(warp::reply::with_status(reply, warp::http::StatusCode::INTERNAL_SERVER_ERROR));
        } else {
            return Err(e);
        }
    }
}

mod handlers {
    use rusqlite::params;
    use warp::{Rejection, http::StatusCode};

    use super::models;
    use super::storage;

    /// Inserts the given `message` into the database if it's valid.
    pub async fn insert_message(message: models::Message, db_pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
        // Validate the message
        if !message.is_valid() { return Err(warp::reject::custom(models::ValidationError)); }
        // Get a database connection
        let db_conn = storage::get_db_conn(&db_pool)?;
        // Insert the message
        match db_conn.execute(
            "INSERT INTO messages (text) VALUES (?1)",
            params![message.text],
        ) {
            Ok(_) => return Ok(StatusCode::OK),
            Err(e) => {
                println!("Couldn't insert message due to error: {:?}.", e);
                return Err(warp::reject::custom(storage::DatabaseError)); 
            }
        }
    }

    /// Returns the last `options.limit` messages from the database.
    pub async fn get_messages(options: models::QueryOptions, db_pool: storage::DatabaseConnectionPool) -> Result<impl warp::Reply, Rejection> {
        // Get a database connection
        let db_conn = storage::get_db_conn(&db_pool)?;
        // Query the database
        let limit = options.limit.unwrap_or(256); // Never return more than 256 messages at once
        let raw_query = format!("SELECT text FROM messages ORDER BY rowid DESC LIMIT {}", limit); // Get the last `limit` messages
        let mut query = match db_conn.prepare(&raw_query) {
            Ok(query) => query,
            Err(e) => { 
                println!("Couldn't create database query due to error: {:?}.", e);
                return Err(warp::reject::custom(storage::DatabaseError));
            }
        };
        let rows = match query.query_map(params![], |row| {
            Ok(models::Message { text: row.get(0)? })
        }) {
            Ok(rows) => rows,
            Err(e) => {
                println!("Couldn't query database due to error: {:?}.", e);
                return Err(warp::reject::custom(storage::DatabaseError));
            }
        };
        // FIXME: It'd be cleaner to do the below using `collect()`, but the compiler has trouble
        // inferring the item type of `rows` in that case.
        let mut messages: Vec<models::Message> = Vec::new();
        for row in rows {
            match row {
                Ok(message) => messages.push(message),
                Err(e) => {
                    println!("Excluding message from response due to database error: {:?}.", e);
                    continue;
                }
            }
        }
        // Return the messages
        return Ok(warp::reply::json(&messages));
    }
}

mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Debug)]
    pub struct ValidationError;
    impl warp::reject::Reject for ValidationError { }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Message {
        pub text: String
    }

    impl Message {

        pub fn is_valid(&self) -> bool {
            return !self.text.is_empty();
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct QueryOptions {
        pub limit: Option<u16>
    }
}

mod storage {
    use r2d2_sqlite::SqliteConnectionManager;

    pub type DatabaseConnection = r2d2::PooledConnection<SqliteConnectionManager>;
    pub type DatabaseConnectionPool = r2d2::Pool<SqliteConnectionManager>;

    #[derive(Debug)]
    pub struct DatabaseError;
    impl warp::reject::Reject for DatabaseError { }

    pub fn get_db_pool() -> DatabaseConnectionPool {
        let db_manager = SqliteConnectionManager::file("messages.db");
        return r2d2::Pool::new(db_manager).unwrap(); // Force
    }

    pub fn get_db_conn(db_pool: &DatabaseConnectionPool) -> Result<DatabaseConnection, warp::reject::Rejection> {
        match db_pool.get() {
            Ok(db_conn) => return Ok(db_conn),
            Err(e) => { 
                println!("Couldn't get database connection from pool due to error: {:?}.", e);
                return Err(warp::reject::custom(DatabaseError));
            }
        }
    }
}