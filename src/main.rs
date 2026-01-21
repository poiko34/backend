mod config;
mod db;
mod auth;
mod models;
mod handlers;
pub mod errors;

use actix_web::{App, HttpServer, web};
use sqlx::MySqlPool;

use crate::handlers::register::register;
use crate::handlers::login::login;
use crate::handlers::balance::balance;
use crate::handlers::recover::recover;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    if let Err(e) = config::init_logger() {
        eprintln!("Logger init failed: {:?}", e);
        return Ok(());
    }

    let pool: MySqlPool = match db::init_db().await {
        Some(p) => p,
        None => return Ok(()),
    };

    println!("Rust backend running on 127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(register)
            .service(login)
            .service(balance)
            .service(recover)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
