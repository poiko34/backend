use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct RegisterForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RecoveryForm {
    pub username: String,
    pub recovery_code: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

// #[derive(Serialize)]
// pub struct RegisterResponse {
//     pub uid: u32,
//     pub username: String,
//     pub recovery_code: String,
// }
