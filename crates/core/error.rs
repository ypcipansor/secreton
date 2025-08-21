use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication failed")]
    AuthenticationError,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, details) = match self {
            AppError::AuthenticationError => (StatusCode::UNAUTHORIZED, self.to_string(), None),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string(), None),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string(), None),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string(), None),
            AppError::InternalServerError(ref msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), Some(msg.clone()))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
                Some(self.to_string()),
            ),
        };

        let body = Json(ErrorResponse {
            error: error_message,
            details,
        });

        (status, body).into_response()
    }
}

impl From<AppError> for anyhow::Error {
    fn from(error: AppError) -> Self {
        anyhow::anyhow!(error)
    }
}

// Helper function to create a not found error
pub fn not_found<T>(message: &str) -> Result<T, AppError> {
    Err(AppError::NotFound(message.to_string()))
}

// Helper function to create a bad request error
pub fn bad_request<T>(message: &str) -> Result<T, AppError> {
    Err(AppError::BadRequest(message.to_string()))
}

// Helper function to create a forbidden error
pub fn forbidden<T>(message: &str) -> Result<T, AppError> {
    Err(AppError::Forbidden(message.to_string()))
}
