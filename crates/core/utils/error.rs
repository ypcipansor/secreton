use axum::{response::{IntoResponse, Response}, http::StatusCode, Json};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Unauthorized")] 
    Unauthorized,
    #[error("Not found")] 
    NotFound,
    #[error("Too many requests")] 
    TooManyRequests,
    #[error("Internal server error")] 
    Internal,
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
        };
        let body = Json(ErrorResponse { error: msg });
        (status, body).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(_err: anyhow::Error) -> Self {
        AppError::Internal
    }
} 