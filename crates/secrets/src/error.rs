//! Secret engine specific error types

use secreton_errors::SecretonError;
use thiserror::Error;

/// Errors specific to secret engine operations
#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Engine not found: {0}")]
    EngineNotFound(String),

    #[error("Engine already exists: {0}")]
    EngineAlreadyExists(String),

    #[error("Invalid engine configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Secret version not found: {0}")]
    SecretVersionNotFound(String),

    #[error("Invalid secret data: {0}")]
    InvalidSecretData(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key operation: {0}")]
    InvalidKeyOperation(String),

    #[error("Backend connection failed: {0}")]
    BackendConnectionFailed(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Backend operation failed: {0}")]
    BackendOperationFailed(String),

    #[error("Lease expired")]
    LeaseExpired,

    #[error("Invalid lease")]
    InvalidLease,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Backend not supported: {0}")]
    BackendNotSupported(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

impl From<SecretError> for SecretonError {
    fn from(err: SecretError) -> Self {
        SecretonError::Internal {
            message: err.to_string(),
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for SecretError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        SecretError::BackendOperationFailed(err.to_string())
    }
}

/// Result type for secret operations
pub type SecretResult<T> = Result<T, SecretError>;
