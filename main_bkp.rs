use actix_web::{get, post, web, App, HttpResponse, HttpServer, HttpRequest};
use serde::{Deserialize, Serialize};
use sqlx::{MySqlPool, Row};
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::{thread_rng, distributions::Alphanumeric, Rng};
use flexi_logger::{Duplicate, Logger, FileSpec, Criterion, Naming, Cleanup};
use log::{info, error};
use once_cell::sync::Lazy;
use std::env;

// ------------------- Константы -------------------
static API_KEY: Lazy<String> = Lazy::new(|| {
    env::var("API_KEY").expect("API_KEY must be set")
});

// ------------------- Структуры -------------------
#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RecoveryForm {
    username: String,
    recovery_code: String,
    new_password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    uid: u32,
    username: String,
    recovery_code: String,
}

// ------------------- Вспомогательные функции -------------------
fn generate_recovery_code() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    Logger::try_with_str("info")?
        .log_to_file(FileSpec::default().directory("logs").basename("api"))
        .duplicate_to_stderr(Duplicate::Warn)
        .rotate(
            Criterion::Size(1024 * 1024),
            Naming::Numbers,
            Cleanup::KeepLogFiles(5),
        )
        .start()?;

    info!("Logger initialized");
    Ok(())
}

fn generate_token() -> String {
    use rand::{RngCore, rngs::OsRng};

    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

async fn authenticate(
    req: &actix_web::HttpRequest,
    pool: &MySqlPool,
) -> Result<u64, HttpResponse> {
    let header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err(HttpResponse::Unauthorized().body("Missing token")),
    };

    let row = match sqlx::query(
        "SELECT user_id FROM sessions
         WHERE token = ? AND expires_at > NOW()"
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(r)) => r,
        _ => return Err(HttpResponse::Unauthorized().body("Invalid token")),
    };

    let uid: u64 = match row.try_get("user_id") {
        Ok(u) => u,
        Err(e) => return Err(HttpResponse::InternalServerError().body("Failed to read user_id")),
    };
    Ok(uid)
}

// ------------------- Эндпоинты -------------------
#[post("/register")]
async fn register(
    pool: web::Data<MySqlPool>,
    req: HttpRequest,
    form: web::Json<RegisterForm>,
) -> HttpResponse {
    info!("POST /register | username={}", form.username);

    // Проверка API ключа
    if req.headers().get("X-API-Key").and_then(|v| v.to_str().ok()) != Some(API_KEY.as_str()) {
        error!("Unauthorized register attempt | username={}", form.username);
        return HttpResponse::Unauthorized().finish();
    }

    // Проверка существующего пользователя
    if let Ok(Some(_)) = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(pool.get_ref())
        .await
    {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "User exists"
        }));
    }

    // Хэширование пароля
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

    // Вставка в БД
    let _ = sqlx::query(
        "INSERT INTO users (username, password_hash, role, balance, recovery_code) VALUES (?, ?, 'buyer', 0.0, ?)"
    )
    .bind(&form.username)
    .bind(&password_hash)
    .bind(&recovery_hash)
    .execute(pool.get_ref())
    .await;

    // Получение id нового пользователя
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

#[post("/login")]
async fn login(
    pool: web::Data<MySqlPool>,
    form: web::Json<LoginForm>,
) -> HttpResponse {
    let row = match sqlx::query(
        "SELECT id, password_hash FROM users WHERE username = ?"
    )
    .bind(&form.username)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(r)) => r,
        _ => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    let uid: u64 = match row.try_get("id") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let hash: String = match row.try_get("password_hash") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let parsed = match argon2::password_hash::PasswordHash::new(&hash) {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    // создаём сессию
    let token = generate_token();

    let res = sqlx::query(
        "INSERT INTO sessions (user_id, token, expires_at)
         VALUES (?, ?, NOW() + INTERVAL 7 DAY)"
    )
    .bind(uid)
    .bind(&token)
    .execute(pool.get_ref())
    .await;

    if res.is_err() {
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().json(LoginResponse { token })
}

#[get("/balance")]
async fn balance(
    pool: web::Data<MySqlPool>,
    req: actix_web::HttpRequest,
) -> HttpResponse {
    let uid = match authenticate(&req, pool.get_ref()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let row = match sqlx::query(
        "SELECT balance FROM users WHERE id = ?"
    )
    .bind(uid)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(r)) => r,
        _ => return HttpResponse::NotFound().body("User not found"),
    };

    let balance: f64 = match row.try_get("balance") {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to read balance"),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "balance": balance
    }))
}

#[post("/recover")]
async fn recover(
    pool: web::Data<MySqlPool>,
    form: web::Json<RecoveryForm>
) -> HttpResponse {
    info!("POST /recover | username={}", form.username);

    let row = match sqlx::query("SELECT id, recovery_code FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            error!("Recovery failed (user not found) | username={}", form.username);
            return HttpResponse::NotFound().body("User not found");
        }
        Err(e) => {
            error!("Database error during recovery | username={} | error={:?}", form.username, e);
            return HttpResponse::InternalServerError().body("Database error");
        }
    };

    let db_code_hash: String = match row.try_get("recovery_code") {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get recovery code | username={} | error={:?}", form.username, e);
            return HttpResponse::InternalServerError().body("Database error");
        }
    };
    let uid: u32 = match row.try_get("id") {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to get user ID | username={} | error={:?}", form.username, e);
            return HttpResponse::InternalServerError().body("Database error");
        }
    };

    let parsed_hash = match argon2::password_hash::PasswordHash::new(&db_code_hash) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to parse recovery code hash | username={} | error={:?}", form.username, e);
            return HttpResponse::InternalServerError().body("Recovery code parse error");
        }
    };

    if Argon2::default().verify_password(form.recovery_code.as_bytes(), &parsed_hash).is_err() {
        error!("Recovery failed (invalid code) | username={}", form.username);
        return HttpResponse::Unauthorized().body("Invalid recovery code");
    }

    // Новый пароль и recovery_code
    let salt = SaltString::generate(&mut thread_rng());
    let password_hash = match Argon2::default().hash_password(form.new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            error!("Failed to hash new password | username={} | error={:?}", form.username, e);
            return HttpResponse::InternalServerError().body("Password hashing failed");
        }
    };
    let new_code = generate_recovery_code();
    let new_code_hash = match Argon2::default().hash_password(new_code.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            error!("Failed to hash new recovery code | username={} | error={:?}", form.username, e);
            return HttpResponse::InternalServerError().body("Recovery code hashing failed");
        }
    };

    if let Err(e) = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(uid)
        .execute(pool.get_ref())
        .await
    {
        error!("Failed to delete old sessions | username={} | error={:?}", form.username, e);
        return HttpResponse::InternalServerError().body("Failed to delete old sessions");
    }

    if let Err(e) = sqlx::query("UPDATE users SET password_hash = ?, recovery_code = ? WHERE id = ?")
        .bind(&password_hash)
        .bind(&new_code_hash)
        .bind(uid)
        .execute(pool.get_ref())
        .await
    {
        error!("Failed to update password/recovery code | username={} | error={:?}", form.username, e);
        return HttpResponse::InternalServerError().body("Database error");
    }

    info!("Password recovered successfully | username={}", form.username);

    #[derive(Serialize)]
    struct RecoveryResponse {
        message: String,
        new_recovery_code: String,
    }

    HttpResponse::Ok().json(RecoveryResponse {
        message: "Password has been reset successfully".to_string(),
        new_recovery_code: new_code,
    })
}

// ------------------- Main -------------------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    if let Err(e) = init_logger() {
        eprintln!("Logger init failed: {:?}", e);
        return Ok(());
    }

    info!("Backend starting...");

    let database_url = match env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            error!("DATABASE_URL not set");
            return Ok(());
        }
    };

    let pool = match MySqlPool::connect(&database_url).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to connect to DB: {:?}", e);
            return Ok(());
        }
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
