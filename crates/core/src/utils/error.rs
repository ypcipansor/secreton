use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use secreton_secrets::error::SecretError;

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

impl From<axum::Error> for AppError {
    fn from(_err: axum::Error) -> Self {
        AppError::Internal
    }
}

impl From<axum::http::Error> for AppError {
    fn from(_err: axum::http::Error) -> Self {
        AppError::Internal
    }
}

impl From<serde_json::Error> for AppError {
    fn from(_err: serde_json::Error) -> Self {
        AppError::Internal
    }
}

impl From<std::io::Error> for AppError {
    fn from(_err: std::io::Error) -> Self {
        AppError::Internal
    }
}

impl From<SecretError> for AppError {
    fn from(err: SecretError) -> Self {
        match err {
            SecretError::EngineNotFound(_) => AppError::NotFound,
            SecretError::SecretNotFound(_) => AppError::NotFound,
            SecretError::InvalidConfiguration(msg) => {
                AppError::BadRequest(msg)
            }
            SecretError::InvalidSecretData(msg) => {
                AppError::BadRequest(msg)
            }
            SecretError::InvalidPath(msg) => AppError::BadRequest(msg),
            SecretError::InvalidOperation(msg) => {
                AppError::BadRequest(msg)
            }
            SecretError::BackendConnectionFailed(_) => {
                AppError::InternalError(err.to_string())
            }
            SecretError::BackendOperationFailed(_) => {
                AppError::InternalError(err.to_string())
            }
            SecretError::NotImplemented(msg) => {
                AppError::BadRequest(msg)
            }
            _ => AppError::InternalError(err.to_string()),
        }
    }
}
