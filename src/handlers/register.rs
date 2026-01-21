use actix_web::{post, web, HttpRequest, HttpResponse};
use sqlx::{MySqlPool, Row};
use log::{info, error};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::thread_rng;

use crate::{models::RegisterForm, auth::generate_recovery_code, config::API_KEY};

#[post("/register")]
pub async fn register(pool: web::Data<MySqlPool>, req: HttpRequest, form: web::Json<RegisterForm>) -> HttpResponse {
    info!("POST /register | username={}", form.username);

    if req.headers().get("X-API-Key").and_then(|v| v.to_str().ok()) != Some(API_KEY.as_str()) {
        error!("Unauthorized register attempt | username={}", form.username);
        return HttpResponse::Unauthorized().finish();
    }

    if let Ok(Some(_)) = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(pool.get_ref())
        .await
    {
        return HttpResponse::Conflict().json(serde_json::json!({ "error": "User exists" }));
    }

    let salt = SaltString::generate(&mut thread_rng());
    let password_hash = Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let recovery_code = generate_recovery_code();
    let recovery_hash = Argon2::default()
        .hash_password(recovery_code.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let _ = sqlx::query(
        "INSERT INTO users (username, password_hash, role, balance, recovery_code) VALUES (?, ?, 'buyer', 0.0, ?)"
    )
    .bind(&form.username)
    .bind(&password_hash)
    .bind(&recovery_hash)
    .execute(pool.get_ref())
    .await;

    let user = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_one(pool.get_ref())
        .await
        .unwrap();

    let uid: u32 = user.try_get("id").unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "uid": uid,
        "username": form.username,
        "recovery_code": recovery_code
    }))
}
