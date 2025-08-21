//! Error handling for the Brankas API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::{ApiResponse, ErrorDetails, ResponseMetadata};

/// API error types
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    #[error("Authorization failed: {message}")]
    Authorization { message: String },

    #[error("Rate limit exceeded: {message}")]
    RateLimit { message: String },

    #[error("Validation error: {message}")]
    Validation { 
        message: String,
        field: Option<String>,
        details: Option<HashMap<String, String>>,
    },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Resource already exists: {resource}")]
    Conflict { resource: String },

    #[error("Service unavailable: {message}")]
    ServiceUnavailable { message: String },

    #[error("Bad request: {message}")]
    BadRequest { message: String },

    #[error("Request timeout")]
    Timeout,

    #[error("Request entity too large")]
    PayloadTooLarge,

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Core error: {0}")]
    Core(#[from] brankas_core::error::CoreError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] brankas_crypto::CryptoError),

    #[error("Storage error: {0}")]
    Storage(#[from] brankas_storage::StorageError),

    #[error("Authentication service error: {0}")]
    Auth(#[from] crate::services::auth::AuthError),
}

impl ApiError {
    /// Get HTTP status code for the error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Authentication { .. } => StatusCode::UNAUTHORIZED,
            Self::Authorization { .. } => StatusCode::FORBIDDEN,
            Self::RateLimit { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Validation { .. } => StatusCode::BAD_REQUEST,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Timeout => StatusCode::REQUEST_TIMEOUT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Core(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Crypto(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Auth(auth_err) => match auth_err {
                crate::services::auth::AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
                crate::services::auth::AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
                crate::services::auth::AuthError::TokenExpired => StatusCode::UNAUTHORIZED,
                crate::services::auth::AuthError::MfaRequired => StatusCode::UNAUTHORIZED,
                crate::services::auth::AuthError::InvalidMfaCode => StatusCode::UNAUTHORIZED,
                crate::services::auth::AuthError::UserNotFound => StatusCode::NOT_FOUND,
                crate::services::auth::AuthError::UserAlreadyExists => StatusCode::CONFLICT,
                crate::services::auth::AuthError::PermissionDenied => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }

    /// Get error code for programmatic handling
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Authentication { .. } => "AUTH_FAILED",
            Self::Authorization { .. } => "AUTHZ_FAILED",
            Self::RateLimit { .. } => "RATE_LIMITED",
            Self::Validation { .. } => "INVALID_REQUEST",
            Self::NotFound { .. } => "NOT_FOUND",
            Self::Conflict { .. } => "RESOURCE_EXISTS",
            Self::BadRequest { .. } => "BAD_REQUEST",
            Self::Timeout => "REQUEST_TIMEOUT",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::ServiceUnavailable { .. } => "SERVICE_UNAVAILABLE",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::Core(_) => "CORE_ERROR",
            Self::Crypto(_) => "CRYPTO_ERROR",
            Self::Storage(_) => "STORAGE_ERROR",
            Self::Auth(auth_err) => match auth_err {
                crate::services::auth::AuthError::InvalidCredentials => "INVALID_CREDENTIALS",
                crate::services::auth::AuthError::InvalidToken => "INVALID_TOKEN",
                crate::services::auth::AuthError::TokenExpired => "TOKEN_EXPIRED",
                crate::services::auth::AuthError::MfaRequired => "MFA_REQUIRED",
                crate::services::auth::AuthError::InvalidMfaCode => "INVALID_MFA_CODE",
                crate::services::auth::AuthError::UserNotFound => "USER_NOT_FOUND",
                crate::services::auth::AuthError::UserAlreadyExists => "USER_EXISTS",
                crate::services::auth::AuthError::PermissionDenied => "PERMISSION_DENIED",
                _ => "AUTH_ERROR",
            },
        }
    }

    /// Get error details for the response
    pub fn get_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Validation { field, details, .. } => {
                let mut error_details = HashMap::new();
                
                if let Some(field) = field {
                    error_details.insert("field".to_string(), serde_json::Value::String(field.clone()));
                }
                
                if let Some(details) = details {
                    error_details.insert("validation_errors".to_string(), serde_json::to_value(details).unwrap_or_default());
                }
                
                if !error_details.is_empty() {
                    Some(serde_json::Value::Object(error_details.into_iter().collect()))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Create authentication error
    pub fn authentication<S: Into<String>>(message: S) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create authorization error
    pub fn authorization<S: Into<String>>(message: S) -> Self {
        Self::Authorization {
            message: message.into(),
        }
    }

    /// Create validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
            field: None,
            details: None,
        }
    }

    /// Create validation error with field
    pub fn validation_field<S: Into<String>, F: Into<String>>(message: S, field: F) -> Self {
        Self::Validation {
            message: message.into(),
            field: Some(field.into()),
            details: None,
        }
    }

    /// Create validation error with details
    pub fn validation_with_details<S: Into<String>>(
        message: S,
        field: Option<String>,
        details: HashMap<String, String>,
    ) -> Self {
        Self::Validation {
            message: message.into(),
            field,
            details: Some(details),
        }
    }

    /// Create not found error
    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    /// Create conflict error
    pub fn conflict<S: Into<String>>(resource: S) -> Self {
        Self::Conflict {
            resource: resource.into(),
        }
    }

    /// Create bad request error
    pub fn bad_request<S: Into<String>>(message: S) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    /// Create rate limit error
    pub fn rate_limit<S: Into<String>>(message: S) -> Self {
        Self::RateLimit {
            message: message.into(),
        }
    }

    /// Create service unavailable error
    pub fn service_unavailable<S: Into<String>>(message: S) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_details = ErrorDetails {
            code: self.error_code().to_string(),
            message: self.to_string(),
            details: self.get_details(),
        };

        let response = ApiResponse {
            success: false,
            data: None::<()>,
            error: Some(error_details),
            metadata: ResponseMetadata::new(),
        };

        (status, Json(response)).into_response()
    }
}

/// Result type alias for API operations
pub type ApiResult<T> = Result<T, ApiError>;

/// Validation error builder
pub struct ValidationErrorBuilder {
    message: String,
    field: Option<String>,
    details: HashMap<String, String>,
}

impl ValidationErrorBuilder {
    /// Create new validation error builder
    pub fn new<S: Into<String>>(message: S) -> Self {
        Self {
            message: message.into(),
            field: None,
            details: HashMap::new(),
        }
    }

    /// Set field name
    pub fn field<S: Into<String>>(mut self, field: S) -> Self {
        self.field = Some(field.into());
        self
    }

    /// Add validation detail
    pub fn detail<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Build the API error
    pub fn build(self) -> ApiError {
        ApiError::validation_with_details(self.message, self.field, self.details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_status_codes() {
        assert_eq!(
            ApiError::authentication("test").status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::authorization("test").status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ApiError::validation("test").status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::not_found("test").status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::conflict("test").status_code(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn test_api_error_codes() {
        assert_eq!(ApiError::authentication("test").error_code(), "AUTH_FAILED");
        assert_eq!(ApiError::authorization("test").error_code(), "AUTHZ_FAILED");
        assert_eq!(ApiError::validation("test").error_code(), "INVALID_REQUEST");
        assert_eq!(ApiError::not_found("test").error_code(), "NOT_FOUND");
        assert_eq!(ApiError::conflict("test").error_code(), "RESOURCE_EXISTS");
    }

    #[test]
    fn test_validation_error_builder() {
        let error = ValidationErrorBuilder::new("Invalid data")
            .field("username")
            .detail("min_length", "3")
            .detail("pattern", "alphanumeric")
            .build();

        match error {
            ApiError::Validation { message, field, details } => {
                assert_eq!(message, "Invalid data");
                assert_eq!(field, Some("username".to_string()));
                assert!(details.is_some());
                let details = details.unwrap();
                assert_eq!(details.get("min_length"), Some(&"3".to_string()));
                assert_eq!(details.get("pattern"), Some(&"alphanumeric".to_string()));
            }
            _ => panic!("Expected validation error"),
        }
    }
}
