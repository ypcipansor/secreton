//! Enterprise feature errors

use thiserror::Error;

/// Enterprise feature operation errors
#[derive(Debug, Error)]
pub enum EnterpriseError {
    #[error("Feature not available: {feature}")]
    FeatureNotAvailable { feature: String },

    #[error("HSM error: {reason}")]
    HsmError { reason: String },

    #[error("AI service error: {reason}")]
    AiError { reason: String },

    #[error("Quantum operation error: {reason}")]
    QuantumError { reason: String },

    #[error("MPC operation failed: {reason}")]
    MpcError { reason: String },

    #[error("Homomorphic encryption error: {reason}")]
    HomomorphicError { reason: String },

    #[error("ZKP verification failed: {reason}")]
    ZkpError { reason: String },

    #[error("Backup operation failed: {reason}")]
    BackupError { reason: String },

    #[error("Security level insufficient: required {required}, got {current}")]
    InsufficientSecurityLevel { required: String, current: String },

    #[error("Configuration error: {field} - {reason}")]
    ConfigError { field: String, reason: String },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Validation failed: {message}")]
    Validation { message: String },

    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },

    #[error("Timeout: {operation}")]
    Timeout { operation: String },

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Internal enterprise error: {0}")]
    InternalError(String),
}

impl EnterpriseError {
    /// Create not found error
    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    /// Create validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }
}