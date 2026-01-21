use actix_web::{get, web, HttpResponse, HttpRequest};
use sqlx::{MySqlPool, Row};
use crate::auth::authenticate;

#[get("/balance")]
pub async fn balance(pool: web::Data<MySqlPool>, req: HttpRequest) -> HttpResponse {
    let uid = match authenticate(&req, pool.get_ref()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let row = match sqlx::query("SELECT balance FROM users WHERE id = ?")
        .bind(uid)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        _ => return HttpResponse::NotFound().body("User not found"),
    };

    let balance: f64 = row.try_get("balance").unwrap();

    HttpResponse::Ok().json(serde_json::json!({ "balance": balance }))
}
