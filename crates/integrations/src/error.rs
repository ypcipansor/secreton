//! Integration errors

use thiserror::Error;

/// Integration operation errors
#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("Connection failed: {provider} - {reason}")]
    ConnectionFailed { provider: String, reason: String },

    #[error("Authentication failed: {provider}")]
    AuthenticationFailed { provider: String },

    #[error("API error: {provider} - {status}: {message}")]
    ApiError {
        provider: String,
        status: u16,
        message: String,
    },

    #[error("Configuration error: {field} - {reason}")]
    ConfigError { field: String, reason: String },

    #[error("Data sync failed: {reason}")]
    SyncError { reason: String },

    #[error("Rate limit exceeded: {provider}")]
    RateLimitExceeded { provider: String },

    #[error("Unsupported operation: {operation}")]
    UnsupportedOperation { operation: String },

    #[error("Timeout: {operation}")]
    Timeout { operation: String },

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Internal error: {0}")]
    InternalError(String),
}
