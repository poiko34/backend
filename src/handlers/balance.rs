use actix_web::{get, web, HttpResponse, HttpRequest};
use sqlx::{MySqlPool, Row};
use crate::auth::authenticate;
use crate::errors::AppError;

#[get("/balance")]
pub async fn balance(
    pool: web::Data<MySqlPool>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    // Аутентификация пользователя
    let uid = authenticate(&req, pool.get_ref())
        .await
        .map_err(|_| AppError::InvalidCredentials)?;

    // Получаем баланс пользователя
    let row = sqlx::query("SELECT balance FROM users WHERE id = ?")
        .bind(uid)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(AppError::DbError)?;

    let row: sqlx::mysql::MySqlRow = match row {
        Some(r) => r,
        None => return Err(AppError::NotFound),
    };

    let balance: f64 = row.try_get("balance").map_err(|_| AppError::Internal)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "balance": balance })))
}
