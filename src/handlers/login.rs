use actix_web::{post, web, HttpResponse};
use sqlx::{MySqlPool, Row};
use argon2::{Argon2, PasswordVerifier};
use crate::models::{LoginForm, LoginResponse};
use crate::auth::generate_token;
use crate::errors::AppError;

#[post("/login")]
pub async fn login(
    pool: web::Data<MySqlPool>,
    form: web::Json<LoginForm>,
) -> Result<HttpResponse, AppError> {
    // Получаем пользователя по username
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(AppError::DbError)?;

    let row: sqlx::mysql::MySqlRow = match row {
        Some(r) => r,
        None => return Err(AppError::InvalidCredentials),
    };

    // Получаем id и хэш пароля
    let uid: u64 = row.try_get("id").map_err(|_| AppError::Internal)?;
    let hash: String = row.try_get("password_hash").map_err(|_| AppError::Internal)?;

    // Проверка пароля
    let parsed = argon2::password_hash::PasswordHash::new(&hash)
        .map_err(|_| AppError::Internal)?;

    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        return Err(AppError::InvalidCredentials);
    }

    // Создание токена сессии
    let token = generate_token();
    sqlx::query(
        "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, NOW() + INTERVAL 1 DAY)"
    )
    .bind(uid)
    .bind(&token)
    .execute(pool.get_ref())
    .await
    .map_err(AppError::DbError)?;

    Ok(HttpResponse::Ok().json(LoginResponse { token }))
}
