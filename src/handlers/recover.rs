use actix_web::{post, web, HttpResponse};
use sqlx::{MySqlPool, Row};
use log::{info, error};
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::thread_rng;
use crate::models::RecoveryForm;
use crate::auth::generate_recovery_code;

#[post("/recover")]
pub async fn recover(pool: web::Data<MySqlPool>, form: web::Json<RecoveryForm>) -> HttpResponse {
    info!("POST /recover | username={}", form.username);

    let row = match sqlx::query("SELECT id, recovery_code FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        _ => return HttpResponse::NotFound().body("User not found"),
    };

    let db_code_hash: String = row.try_get("recovery_code").unwrap();
    let uid: u32 = row.try_get("id").unwrap();

    let parsed_hash = argon2::password_hash::PasswordHash::new(&db_code_hash).unwrap();
    if Argon2::default().verify_password(form.recovery_code.as_bytes(), &parsed_hash).is_err() {
        error!("Recovery failed | username={}", form.username);
        return HttpResponse::Unauthorized().body("Invalid recovery code");
    }

    let salt = SaltString::generate(&mut thread_rng());
    let password_hash = Argon2::default().hash_password(form.new_password.as_bytes(), &salt).unwrap().to_string();
    let new_code = generate_recovery_code();
    let new_code_hash = Argon2::default().hash_password(new_code.as_bytes(), &salt).unwrap().to_string();

    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(uid).execute(pool.get_ref()).await;
    let _ = sqlx::query("UPDATE users SET password_hash = ?, recovery_code = ? WHERE id = ?")
        .bind(&password_hash)
        .bind(&new_code_hash)
        .bind(uid)
        .execute(pool.get_ref())
        .await;

    #[derive(serde::Serialize)]
    struct RecoveryResponse { message: String, new_recovery_code: String }

    HttpResponse::Ok().json(RecoveryResponse {
        message: "Password has been reset successfully".to_string(),
        new_recovery_code: new_code,
    })
}
