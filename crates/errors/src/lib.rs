//! # Secreton Errors
//!
//! Unified error handling system for all Secreton crates.
//! Provides consistent error types, HTTP responses, and error handling utilities.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use secreton_common::{ApiResponse, Result as CommonResult};
use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;

/// Unified error type for all Secreton operations
#[derive(Debug, Error)]
pub enum SecretonError {
    // Authentication & Authorization
    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    #[error("Authorization failed: {message}")]
    Authorization { message: String },

    #[error("Token expired")]
    TokenExpired,

    #[error("Token invalid: {reason}")]
    TokenInvalid { reason: String },

    #[error("Token revoked")]
    TokenRevoked,

    #[error("Token not found: {token}")]
    TokenNotFound { token: String },

    #[error("Token renewal failed: {reason}")]
    TokenRenewalFailed { reason: String },

    #[error("Insufficient permissions: required {required}")]
    InsufficientPermissions { required: String },

    // User Management
    #[error("User not found: {username}")]
    UserNotFound { username: String },

    #[error("User already exists: {username}")]
    UserAlreadyExists { username: String },

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account disabled: {username}")]
    AccountDisabled { username: String },

    #[error("Account locked: {username}")]
    AccountLocked { username: String },

    #[error("Password expired: {username}")]
    PasswordExpired { username: String },

    #[error("Hashing failed: {message}")]
    HashingFailed { message: String },

    // MFA
    #[error("MFA required")]
    MfaRequired,

    #[error("MFA credential error: {message}")]
    MfaCredentialError { message: String },

    #[error("MFA authentication error: {message}")]
    MfaAuthError { message: String },

    #[error("MFA already configured: {method}")]
    MfaAlreadyConfigured { method: String },

    #[error("MFA not configured: {user}")]
    MfaNotConfigured { user: String },

    #[error("MFA code reused")]
    MfaCodeReused,

    #[error("Recovery code used")]
    RecoveryCodeUsed,

    #[error("Recovery code not found")]
    RecoveryCodeNotFound,

    // Agent
    #[error("Agent configuration error: {message}")]
    AgentConfigError { message: String },

    #[error("Agent sink write error: {message}")]
    AgentSinkWriteError { message: String },

    #[error("Agent renewal error: {message}")]
    AgentRenewalError { message: String },

    // Authenticated Keys
    #[error("Authenticated key authentication error: {message}")]
    AuthenticatedKeyAuthError { message: String },

    #[error("Authenticated key permission error: {message}")]
    AuthenticatedKeyPermissionError { message: String },

    // Identity
    #[error("Entity not found: {entity}")]
    EntityNotFound { entity: String },

    #[error("Alias exists: {alias}")]
    AliasExists { alias: String },

    #[error("Alias not found: {alias}")]
    AliasNotFound { alias: String },

    #[error("Entity self merge not allowed")]
    EntitySelfMerge,

    // Resource Management
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Resource already exists: {resource}")]
    AlreadyExists { resource: String },

    #[error("Resource conflict: {message}")]
    Conflict { message: String },

    // Validation
    #[error("Validation failed: {message}")]
    Validation { message: String },

    #[error("Invalid input: {field} - {reason}")]
    InvalidInput { field: String, reason: String },

    // Service & Infrastructure
    #[error("Service unavailable: {service}")]
    ServiceUnavailable { service: String },

    #[error("Database error: {message}")]
    Database { message: String },

    #[error("Cache error: {message}")]
    Cache { message: String },

    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Timeout occurred: {operation}")]
    Timeout { operation: String },

    // Security & Compliance
    #[error("Security violation: {violation}")]
    SecurityViolation { violation: String },

    #[error("Policy violation: {policy} - {reason}")]
    PolicyViolation { policy: String, reason: String },

    #[error("Compliance violation: {standard} - {requirement}")]
    ComplianceViolation { standard: String, requirement: String },

    #[error("Audit error: {message}")]
    Audit { message: String },

    // Cryptography
    #[error("Cryptographic error: {message}")]
    Cryptographic { message: String },

    #[error("Key error: {message}")]
    Key { message: String },

    #[error("Encryption error: {message}")]
    Encryption { message: String },

    #[error("Decryption error: {message}")]
    Decryption { message: String },

    // Rate Limiting & Quotas
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Quota exceeded: {resource} limit {limit}, used {used}")]
    QuotaExceeded {
        resource: String,
        limit: u64,
        used: u64
    },

    // Configuration
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    // IO & System
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("TOML serialization error: {0}")]
    TomlSerialization(#[from] toml::ser::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDeserialization(#[from] toml::de::Error),

    #[error("Parse error: {message}")]
    Parse { message: String },

    // Generic
    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Unknown error: {message}")]
    Unknown { message: String },
}

/// HTTP status code mapping for errors
impl SecretonError {
    /// Get the appropriate HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            // Authentication
            SecretonError::Authentication { .. } => StatusCode::UNAUTHORIZED,
            SecretonError::Authorization { .. } => StatusCode::FORBIDDEN,
            SecretonError::TokenExpired => StatusCode::UNAUTHORIZED,
            SecretonError::TokenInvalid { .. } => StatusCode::UNAUTHORIZED,
            SecretonError::TokenRevoked => StatusCode::UNAUTHORIZED,
            SecretonError::TokenNotFound { .. } => StatusCode::NOT_FOUND,
            SecretonError::TokenRenewalFailed { .. } => StatusCode::BAD_REQUEST,
            SecretonError::InsufficientPermissions { .. } => StatusCode::FORBIDDEN,

            // User Management
            SecretonError::UserNotFound { .. } => StatusCode::NOT_FOUND,
            SecretonError::UserAlreadyExists { .. } => StatusCode::CONFLICT,
            SecretonError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            SecretonError::AccountDisabled { .. } => StatusCode::FORBIDDEN,
            SecretonError::AccountLocked { .. } => StatusCode::LOCKED,
            SecretonError::PasswordExpired { .. } => StatusCode::UNAUTHORIZED,
            SecretonError::HashingFailed { .. } => StatusCode::INTERNAL_SERVER_ERROR,

            // MFA
            SecretonError::MfaRequired => StatusCode::UNAUTHORIZED,
            SecretonError::MfaCredentialError { .. } => StatusCode::BAD_REQUEST,
            SecretonError::MfaAuthError { .. } => StatusCode::UNAUTHORIZED,
            SecretonError::MfaAlreadyConfigured { .. } => StatusCode::CONFLICT,
            SecretonError::MfaNotConfigured { .. } => StatusCode::BAD_REQUEST,
            SecretonError::MfaCodeReused => StatusCode::BAD_REQUEST,
            SecretonError::RecoveryCodeUsed => StatusCode::BAD_REQUEST,
            SecretonError::RecoveryCodeNotFound => StatusCode::NOT_FOUND,

            // Agent
            SecretonError::AgentConfigError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::AgentSinkWriteError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::AgentRenewalError { .. } => StatusCode::BAD_REQUEST,

            // Authenticated Keys
            SecretonError::AuthenticatedKeyAuthError { .. } => StatusCode::UNAUTHORIZED,
            SecretonError::AuthenticatedKeyPermissionError { .. } => StatusCode::FORBIDDEN,

            // Identity
            SecretonError::EntityNotFound { .. } => StatusCode::NOT_FOUND,
            SecretonError::AliasExists { .. } => StatusCode::CONFLICT,
            SecretonError::AliasNotFound { .. } => StatusCode::NOT_FOUND,
            SecretonError::EntitySelfMerge => StatusCode::BAD_REQUEST,

            // Resources
            SecretonError::NotFound { .. } => StatusCode::NOT_FOUND,
            SecretonError::AlreadyExists { .. } => StatusCode::CONFLICT,
            SecretonError::Conflict { .. } => StatusCode::CONFLICT,

            // Validation
            SecretonError::Validation { .. } => StatusCode::BAD_REQUEST,
            SecretonError::InvalidInput { .. } => StatusCode::BAD_REQUEST,

            // Service issues
            SecretonError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            SecretonError::Database { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::Cache { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::Network { .. } => StatusCode::BAD_GATEWAY,
            SecretonError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,

            // Security
            SecretonError::SecurityViolation { .. } => StatusCode::FORBIDDEN,
            SecretonError::PolicyViolation { .. } => StatusCode::FORBIDDEN,
            SecretonError::ComplianceViolation { .. } => StatusCode::FORBIDDEN,
            SecretonError::Audit { .. } => StatusCode::INTERNAL_SERVER_ERROR,

            // Crypto
            SecretonError::Cryptographic { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::Key { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::Encryption { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::Decryption { .. } => StatusCode::INTERNAL_SERVER_ERROR,

            // Limits
            SecretonError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            SecretonError::QuotaExceeded { .. } => StatusCode::INSUFFICIENT_STORAGE,

            // Configuration
            SecretonError::Configuration { .. } => StatusCode::INTERNAL_SERVER_ERROR,

            // System
            SecretonError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::TomlSerialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::TomlDeserialization(_) => StatusCode::BAD_REQUEST,
            SecretonError::Parse { .. } => StatusCode::BAD_REQUEST,

            // Generic
            SecretonError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            SecretonError::Unknown { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Check if this error should be logged as a warning
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            SecretonError::RateLimitExceeded
                | SecretonError::Timeout { .. }
                | SecretonError::Network { .. }
        )
    }

    /// Check if this error should be logged as an error
    pub fn is_error(&self) -> bool {
        !matches!(
            self,
            SecretonError::NotFound { .. }
                | SecretonError::AlreadyExists { .. }
                | SecretonError::Validation { .. }
                | SecretonError::InvalidInput { .. }
                | SecretonError::RateLimitExceeded
        )
    }

    /// Get error category for metrics/monitoring
    pub fn category(&self) -> &'static str {
        match self {
            SecretonError::Authentication { .. }
            | SecretonError::Authorization { .. }
            | SecretonError::TokenExpired
            | SecretonError::TokenInvalid { .. }
            | SecretonError::TokenRevoked
            | SecretonError::TokenNotFound { .. }
            | SecretonError::TokenRenewalFailed { .. }
            | SecretonError::InsufficientPermissions { .. }
            | SecretonError::UserNotFound { .. }
            | SecretonError::UserAlreadyExists { .. }
            | SecretonError::InvalidCredentials
            | SecretonError::AccountDisabled { .. }
            | SecretonError::AccountLocked { .. }
            | SecretonError::PasswordExpired { .. }
            | SecretonError::HashingFailed { .. }
            | SecretonError::MfaRequired
            | SecretonError::MfaCredentialError { .. }
            | SecretonError::MfaAuthError { .. }
            | SecretonError::MfaAlreadyConfigured { .. }
            | SecretonError::MfaNotConfigured { .. }
            | SecretonError::MfaCodeReused
            | SecretonError::RecoveryCodeUsed
            | SecretonError::RecoveryCodeNotFound
            | SecretonError::AgentConfigError { .. }
            | SecretonError::AgentSinkWriteError { .. }
            | SecretonError::AgentRenewalError { .. }
            | SecretonError::AuthenticatedKeyAuthError { .. }
            | SecretonError::AuthenticatedKeyPermissionError { .. } => "authentication",

            SecretonError::NotFound { .. }
            | SecretonError::AlreadyExists { .. }
            | SecretonError::Conflict { .. }
            | SecretonError::EntityNotFound { .. }
            | SecretonError::AliasExists { .. }
            | SecretonError::AliasNotFound { .. }
            | SecretonError::EntitySelfMerge => "resource",

            SecretonError::Validation { .. } | SecretonError::InvalidInput { .. } => "validation",

            SecretonError::ServiceUnavailable { .. }
            | SecretonError::Database { .. }
            | SecretonError::Cache { .. }
            | SecretonError::Network { .. }
            | SecretonError::Timeout { .. } => "infrastructure",

            SecretonError::SecurityViolation { .. }
            | SecretonError::PolicyViolation { .. }
            | SecretonError::ComplianceViolation { .. }
            | SecretonError::Audit { .. } => "security",

            SecretonError::Cryptographic { .. }
            | SecretonError::Key { .. }
            | SecretonError::Encryption { .. }
            | SecretonError::Decryption { .. } => "cryptography",

            SecretonError::RateLimitExceeded | SecretonError::QuotaExceeded { .. } => "limits",

            SecretonError::Configuration { .. } => "configuration",

            SecretonError::Io(_) | SecretonError::Serialization(_) | SecretonError::TomlSerialization(_) | SecretonError::TomlDeserialization(_) | SecretonError::Parse { .. } => "system",

            SecretonError::Internal { .. } | SecretonError::Unknown { .. } => "internal",
        }
    }
}

/// HTTP response implementation for Axum
impl IntoResponse for SecretonError {
    fn into_response(self) -> Response {
        let status_code = self.status_code();
        let error_message = self.to_string();

        // Log the error appropriately
        if self.is_error() {
            tracing::error!("API Error [{}]: {}", status_code, error_message);
        } else if self.is_warning() {
            tracing::warn!("API Warning [{}]: {}", status_code, error_message);
        } else {
            tracing::info!("API Info [{}]: {}", status_code, error_message);
        }

        let mut metadata = HashMap::new();
        metadata.insert(
            "category".to_string(),
            serde_json::Value::String(self.category().to_string()),
        );
        metadata.insert(
            "timestamp".to_string(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );

        let api_response = ApiResponse::<()>::error_with_metadata(error_message, metadata);
        let body = Json(api_response);

        (status_code, body).into_response()
    }
}

/// Type alias for Results using SecretonError
pub type Result<T> = std::result::Result<T, SecretonError>;

/// Convert from common Result to Secreton Result
impl From<CommonResult<()>> for SecretonError {
    fn from(err: CommonResult<()>) -> Self {
        SecretonError::Internal {
            message: format!("{:?}", err),
        }
    }
}

/// Convert from anyhow::Error to SecretonError
impl From<anyhow::Error> for SecretonError {
    fn from(err: anyhow::Error) -> Self {
        SecretonError::Internal {
            message: err.to_string(),
        }
    }
}

/// Convert from KeyManagerError to SecretonError
impl From<secreton_crypto::advanced_key_manager::KeyManagerError> for SecretonError {
    fn from(err: secreton_crypto::advanced_key_manager::KeyManagerError) -> Self {
        match err {
            secreton_crypto::advanced_key_manager::KeyManagerError::KeyNotFound(key) => {
                SecretonError::Key { message: format!("Key not found: {}", key) }
            }
            secreton_crypto::advanced_key_manager::KeyManagerError::InvalidKeyFormat(msg) => {
                SecretonError::Cryptographic { message: format!("Invalid key format: {}", msg) }
            }
            secreton_crypto::advanced_key_manager::KeyManagerError::InsufficientShares(msg) => {
                SecretonError::Cryptographic { message: format!("Insufficient shares: {}", msg) }
            }
            secreton_crypto::advanced_key_manager::KeyManagerError::DerivationFailed(msg) => {
                SecretonError::Cryptographic { message: format!("Key derivation failed: {}", msg) }
            }
            secreton_crypto::advanced_key_manager::KeyManagerError::EscrowFailed(msg) => {
                SecretonError::Cryptographic { message: format!("Escrow failed: {}", msg) }
            }
        }
    }
}

/// Error response structure for JSON API
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    category: String,
    timestamp: String,
}

/// Utility functions for error handling
pub mod utils {
    use super::*;

    /// Create an authentication error
    pub fn auth_error(message: impl Into<String>) -> SecretonError {
        SecretonError::Authentication {
            message: message.into(),
        }
    }

    /// Create an authorization error
    pub fn authz_error(message: impl Into<String>) -> SecretonError {
        SecretonError::Authorization {
            message: message.into(),
        }
    }

    /// Create a not found error
    pub fn not_found(resource: impl Into<String>) -> SecretonError {
        SecretonError::NotFound {
            resource: resource.into(),
        }
    }

    /// Create a validation error
    pub fn validation_error(message: impl Into<String>) -> SecretonError {
        SecretonError::Validation {
            message: message.into(),
        }
    }

    /// Create an internal error
    pub fn internal_error(message: impl Into<String>) -> SecretonError {
        SecretonError::Internal {
            message: message.into(),
        }
    }

    /// Create a service unavailable error
    pub fn service_unavailable(service: impl Into<String>) -> SecretonError {
        SecretonError::ServiceUnavailable {
            service: service.into(),
        }
    }

    /// Convert an error to an API response
    pub fn to_api_response<T>(result: Result<T>) -> ApiResponse<T> {
        match result {
            Ok(data) => ApiResponse::success(data),
            Err(err) => {
                let error_message = err.to_string();
                let mut metadata = HashMap::new();
                metadata.insert(
                    "category".to_string(),
                    serde_json::Value::String(err.category().to_string()),
                );
                metadata.insert(
                    "status_code".to_string(),
                    serde_json::Value::Number(err.status_code().as_u16().into()),
                );
                ApiResponse::error_with_metadata(error_message, metadata)
            }
        }
    }
}