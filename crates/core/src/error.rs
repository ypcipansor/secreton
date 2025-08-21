//! Error handling for core operations.

use thiserror::Error;

/// Core system errors
#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Invalid configuration: {message}")]
    Configuration { message: String },

    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    #[error("Authorization failed: {message}")]  
    Authorization { message: String },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Resource already exists: {resource}")]
    AlreadyExists { resource: String },

    #[error("Invalid operation: {message}")]
    InvalidOperation { message: String },

    #[error("Validation failed: {message}")]
    Validation { message: String },

    #[error("Service unavailable: {message}")]
    ServiceUnavailable { message: String },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Timeout occurred: {operation}")]
    Timeout { operation: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl CoreError {
    /// Create configuration error
    pub fn configuration<S: Into<String>>(message: S) -> Self {
        Self::Configuration {
            message: message.into(),
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

    /// Create not found error
    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    /// Create already exists error
    pub fn already_exists<S: Into<String>>(resource: S) -> Self {
        Self::AlreadyExists {
            resource: resource.into(),
        }
    }

    /// Create invalid operation error
    pub fn invalid_operation<S: Into<String>>(message: S) -> Self {
        Self::InvalidOperation {
            message: message.into(),
        }
    }

    /// Create network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Internal(anyhow::anyhow!("Network error: {}", message.into()))
    }

    /// Create database error
    pub fn database<S: Into<String>>(message: S) -> Self {
        Self::Internal(anyhow::anyhow!("Database error: {}", message.into()))
    }

    /// Create validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Create service unavailable error
    pub fn service_unavailable<S: Into<String>>(message: S) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }

    /// Create timeout error
    pub fn timeout<S: Into<String>>(operation: S) -> Self {
        Self::Timeout {
            operation: operation.into(),
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ServiceUnavailable { .. } | Self::RateLimitExceeded | Self::Timeout { .. }
        )
    }

    /// Check if error is a client error
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::Authentication { .. }
                | Self::Authorization { .. }
                | Self::NotFound { .. }
                | Self::AlreadyExists { .. }
                | Self::InvalidOperation { .. }
                | Self::Validation { .. }
        )
    }

    /// Check if error is a server error
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            Self::ServiceUnavailable { .. }
                | Self::RateLimitExceeded
                | Self::Timeout { .. }
                | Self::Io(_)
                | Self::Serialization(_)
                | Self::Internal(_)
        )
    }

    /// Get error category
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::Authentication { .. } => ErrorCategory::Security,
            Self::Authorization { .. } => ErrorCategory::Security,
            Self::NotFound { .. } => ErrorCategory::NotFound,
            Self::AlreadyExists { .. } => ErrorCategory::Conflict,
            Self::InvalidOperation { .. } => ErrorCategory::Business,
            Self::Validation { .. } => ErrorCategory::Validation,
            Self::ServiceUnavailable { .. } => ErrorCategory::Service,
            Self::RateLimitExceeded => ErrorCategory::RateLimit,
            Self::Timeout { .. } => ErrorCategory::Timeout,
            Self::Configuration { .. } => ErrorCategory::Configuration,
            Self::Io(_) => ErrorCategory::System,
            Self::Serialization(_) => ErrorCategory::System,
            Self::Internal(_) => ErrorCategory::System,
        }
    }
}

/// Error categories for grouping and handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Security-related errors (authentication, authorization)
    Security,
    
    /// Resource not found errors
    NotFound,
    
    /// Resource conflict errors (already exists)
    Conflict,
    
    /// Business logic errors
    Business,
    
    /// Input validation errors
    Validation,
    
    /// Service availability errors
    Service,
    
    /// Rate limiting errors
    RateLimit,
    
    /// Timeout errors
    Timeout,
    
    /// Configuration errors
    Configuration,
    
    /// System-level errors (IO, serialization, etc.)
    System,
}

impl ErrorCategory {
    /// Get category name
    pub fn name(&self) -> &'static str {
        match self {
            ErrorCategory::Security => "security",
            ErrorCategory::NotFound => "not_found",
            ErrorCategory::Conflict => "conflict",
            ErrorCategory::Business => "business",
            ErrorCategory::Validation => "validation",
            ErrorCategory::Service => "service",
            ErrorCategory::RateLimit => "rate_limit",
            ErrorCategory::Timeout => "timeout",
            ErrorCategory::Configuration => "configuration",
            ErrorCategory::System => "system",
        }
    }
}

/// Result type alias for core operations
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        let auth_error = CoreError::authentication("invalid token");
        assert_eq!(auth_error.category(), ErrorCategory::Security);
        assert!(auth_error.is_client_error());
        assert!(!auth_error.is_retryable());

        let service_error = CoreError::service_unavailable("database down");
        assert_eq!(service_error.category(), ErrorCategory::Service);
        assert!(service_error.is_server_error());
        assert!(service_error.is_retryable());
    }

    #[test]
    fn test_error_construction() {
        let error = CoreError::not_found("user/123");
        match error {
            CoreError::NotFound { resource } => {
                assert_eq!(resource, "user/123");
            }
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_retryable_errors() {
        assert!(CoreError::service_unavailable("test").is_retryable());
        assert!(CoreError::RateLimitExceeded.is_retryable());
        assert!(CoreError::timeout("operation").is_retryable());
        
        assert!(!CoreError::authentication("test").is_retryable());
        assert!(!CoreError::validation("test").is_retryable());
    }
}
