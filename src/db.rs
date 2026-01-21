use sqlx::MySqlPool;
use std::env;
use log::error;

pub async fn init_db() -> Option<MySqlPool> {
    let database_url = match env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            error!("DATABASE_URL not set");
            return None;
        }
    };

    match MySqlPool::connect(&database_url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            error!("Failed to connect to DB: {:?}", e);
            None
        }
    }
}
