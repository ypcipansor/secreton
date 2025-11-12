use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
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

// TODO: Add implementation for the secrets_impl module when it's available
// impl From<crate::secrets::secrets_impl::engine::SecretsError> for AppError {
//     fn from(err: crate::secrets::secrets_impl::engine::SecretsError) -> Self {
//         match err {
//             crate::secrets::secrets_impl::engine::SecretsError::NotFound(_) => AppError::NotFound,
//             crate::secrets::secrets_impl::engine::SecretsError::PermissionDenied(_) => {
//                 AppError::Forbidden(err.to_string())
//             }
//             crate::secrets::secrets_impl::engine::SecretsError::InvalidData(msg) => {
//                 AppError::BadRequest(msg)
//             }
//             crate::secrets::secrets_impl::engine::SecretsError::InvalidConfiguration(msg) => {
//                 AppError::BadRequest(msg)
//             }
//             _ => AppError::InternalError(err.to_string()),
//         }
//     }
// }
