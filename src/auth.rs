use actix_web::{HttpRequest, HttpResponse};
use sqlx::{MySqlPool, Row};
use rand::{thread_rng, Rng, distributions::Alphanumeric, rngs::OsRng};
use rand::RngCore;

pub fn generate_recovery_code() -> String {
    thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect()
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub async fn authenticate(req: &HttpRequest, pool: &MySqlPool) -> Result<u64, HttpResponse> {
    let header = req.headers().get("Authorization").and_then(|h| h.to_str().ok());
    let token = match header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err(HttpResponse::Unauthorized().body("Missing token")),
    };

    let row = match sqlx::query("SELECT user_id FROM sessions WHERE token = ? AND expires_at > NOW()")
        .bind(token)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(r)) => r,
        _ => return Err(HttpResponse::Unauthorized().body("Invalid token")),
    };

    match row.try_get("user_id") {
        Ok(uid) => Ok(uid),
        Err(_) => Err(HttpResponse::InternalServerError().body("Failed to read user_id")),
    }
}
