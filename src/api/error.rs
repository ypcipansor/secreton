//! API error handling

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// API error type
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Too many requests: {0}")]
    TooManyRequests(String),
    
    #[error("Internal server error: {0}")]
    InternalServerError(String),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl ApiError {
    /// Create a new bad request error
    pub fn bad_request(message: &str) -> Self {
        Self::BadRequest(message.to_string())
    }
    
    /// Create a new unauthorized error
    pub fn unauthorized(message: &str) -> Self {
        Self::Unauthorized(message.to_string())
    }
    
    /// Create a new forbidden error
    pub fn forbidden(message: &str) -> Self {
        Self::Forbidden(message.to_string())
    }
    
    /// Create a new not found error
    pub fn not_found(message: &str) -> Self {
        Self::NotFound(message.to_string())
    }
    
    /// Create a new conflict error
    pub fn conflict(message: &str) -> Self {
        Self::Conflict(message.to_string())
    }
    
    /// Create a new too many requests error
    pub fn too_many_requests(message: &str) -> Self {
        Self::TooManyRequests(message.to_string())
    }
    
    /// Create a new internal server error
    pub fn internal_error(message: &str) -> Self {
        Self::InternalServerError(message.to_string())
    }
    
    /// Create a new not implemented error
    pub fn not_implemented(message: &str) -> Self {
        Self::NotImplemented(message.to_string())
    }
    
    /// Create a new service unavailable error
    pub fn service_unavailable(message: &str) -> Self {
        Self::ServiceUnavailable(message.to_string())
    }
    
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = json!({
            "error": {
                "code": status.as_u16(),
                "message": self.to_string(),
            }
        });
        
        (status, Json(body)).into_response()
    }
}

// Implement From for common error types
impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => Self::not_found("Resource not found"),
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                Self::conflict("Resource already exists")
            }
            sqlx::Error::Database(db_err) if db_err.is_foreign_key_violation() => {
                Self::bad_request("Invalid reference")
            }
            _ => Self::internal_error(&format!("Database error: {}", err)),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                Self::unauthorized("Token has expired")
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                Self::unauthorized("Invalid token")
            }
            _ => Self::unauthorized(&format!("Authentication error: {}", err)),
        }
    }
}

impl From<argon2::password_hash::Error> for ApiError {
    fn from(err: argon2::password_hash::Error) -> Self {
        match err {
            argon2::password_hash::Error::Password => {
                Self::unauthorized("Invalid username or password")
            }
            _ => Self::internal_error(&format!("Password hashing error: {}", err)),
        }
    }
}

impl From<validator::ValidationErrors> for ApiError {
    fn from(err: validator::ValidationErrors) -> Self {
        let messages: Vec<String> = err
            .field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |e| {
                    if let Some(message) = &e.message {
                        format!("{}: {}", field, message)
                    } else {
                        format!("Invalid value for {}", field)
                    }
                })
            })
            .collect();
            
        Self::bad_request(&messages.join(", "))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => Self::not_found("Resource not found"),
            std::io::ErrorKind::PermissionDenied => {
                Self::forbidden("Permission denied")
            }
            _ => Self::internal_error(&format!("I/O error: {}", err)),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        Self::bad_request(&format!("Invalid JSON: {}", err))
    }
}

impl From<uuid::Error> for ApiError {
    fn from(err: uuid::Error) -> Self {
        Self::bad_request(&format!("Invalid UUID: {}", err))
    }
}

impl From<chrono::ParseError> for ApiError {
    fn from(err: chrono::ParseError) -> Self {
        Self::bad_request(&format!("Invalid date/time: {}", err))
    }
}

impl From<base64::DecodeError> for ApiError {
    fn from(err: base64::DecodeError) -> Self {
        Self::bad_request(&format!("Invalid base64: {}", err))
    }
}
