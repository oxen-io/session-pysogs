use serde::{Deserialize, Serialize};
use warp::Filter;

#[derive(Deserialize, Serialize)]
struct Message {
    text: String
}

#[tokio::main]
async fn main() {
    
    // POST /messages
    let send_message = warp::post()
        .and(warp::path("messages"))
        // Only accept bodies smaller than 256 kb
        .and(warp::body::content_length_limit(1024 * 256))
        .and(warp::body::json())
        .map(|message: Message| {
            warp::reply::json(&message)
        });

    warp::serve(send_message).run(([127, 0, 0, 1], 3030)).await;
}
