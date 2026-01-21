use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),

    #[error("User not found")]
    NotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Internal server error")]
    Internal,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::DbError(_) | AppError::Internal => {
                HttpResponse::InternalServerError().json("Internal server error")
            }
            AppError::NotFound => HttpResponse::NotFound().json("Not found"),
            AppError::InvalidCredentials => HttpResponse::Unauthorized().json("Invalid credentials"),
        }
    }
}
