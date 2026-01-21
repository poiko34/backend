use actix_web::{post, web, HttpResponse};
use sqlx::{MySqlPool, Row};
use argon2::{Argon2, PasswordVerifier};
use crate::models::{LoginForm, LoginResponse};
use crate::auth::generate_token;

#[post("/login")]
pub async fn login(pool: web::Data<MySqlPool>, form: web::Json<LoginForm>) -> HttpResponse {
    let row = match sqlx::query("SELECT id, password_hash FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        _ => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    let uid: u64 = row.try_get("id").unwrap();
    let hash: String = row.try_get("password_hash").unwrap();

    let parsed = argon2::password_hash::PasswordHash::new(&hash).unwrap();
    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    let token = generate_token();
    let _ = sqlx::query("INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, NOW() + INTERVAL 1 DAY)")
        .bind(uid)
        .bind(&token)
        .execute(pool.get_ref())
        .await;

    HttpResponse::Ok().json(LoginResponse { token })
}
