//! Comprehensive error handling for the transit engine

use thiserror::Error;
use serde::{Serialize, Deserialize};
use std::fmt;

/// Comprehensive cryptographic error types for the transit engine
#[derive(Error, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CryptoError {
    // Key management errors
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Key version not found: {0}")]
    KeyVersionNotFound(u32),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Key rotation failed: {0}")]
    KeyRotationFailed(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    // Encryption/Decryption errors
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),
    
    // Signing/Verification errors
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    // Parameter validation errors
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid nonce/IV length")]
    InvalidNonceLength,
    
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    
    // Usage and policy errors
    #[error("Invalid usage: {0}")]
    InvalidUsage(String),
    
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
    
    // System errors
    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Random generation failed")]
    RandomGenerationFailed,
    
    #[error("Hash operation failed: {0}")]
    HashFailed(String),
    
    // Audit and compliance errors
    #[error("Audit logging failed: {0}")]
    AuditLogFailed(String),
    
    #[error("Compliance check failed: {0}")]
    ComplianceFailed(String),
    
    // Timeout and resource errors
    #[error("Operation timeout")]
    OperationTimeout,
    
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
    
    #[error("Concurrent operation limit exceeded")]
    ConcurrencyLimitExceeded,
    
    // Batch operation errors
    #[error("Batch operation failed: {0}")]
    BatchOperationFailed(String),
    
    #[error("Batch size exceeded: {current} > {max}")]
    BatchSizeExceeded { current: usize, max: usize },
}

/// Type alias for Results with CryptoError
pub type CryptoResult<T> = Result<T, CryptoError>;

impl CryptoError {
    /// Check if error is recoverable (temporary)
    pub fn is_recoverable(&self) -> bool {
        match self {
            CryptoError::NetworkError(_) |
            CryptoError::OperationTimeout |
            CryptoError::ResourceExhausted(_) |
            CryptoError::ConcurrencyLimitExceeded => true,
            _ => false,
        }
    }
    
    /// Check if error should be retried
    pub fn should_retry(&self) -> bool {
        match self {
            CryptoError::OperationTimeout |
            CryptoError::NetworkError(_) |
            CryptoError::ConcurrencyLimitExceeded => true,
            _ => false,
        }
    }
    
    /// Get error severity level
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            CryptoError::Internal(_) |
            CryptoError::KeyGenerationFailed(_) |
            CryptoError::ConfigurationError(_) => ErrorSeverity::Critical,
            
            CryptoError::PolicyViolation(_) |
            CryptoError::PermissionDenied(_) |
            CryptoError::ComplianceFailed(_) => ErrorSeverity::High,
            
            CryptoError::EncryptionFailed(_) |
            CryptoError::DecryptionFailed(_) |
            CryptoError::SigningFailed(_) |
            CryptoError::VerificationFailed(_) => ErrorSeverity::Medium,
            
            CryptoError::InvalidParameter(_) |
            CryptoError::InvalidUsage(_) |
            CryptoError::KeyNotFound(_) => ErrorSeverity::Low,
            
            _ => ErrorSeverity::Medium,
        }
    }
    
    /// Get error category for metrics and monitoring
    pub fn category(&self) -> ErrorCategory {
        match self {
            CryptoError::KeyAlreadyExists(_) |
            CryptoError::KeyNotFound(_) |
            CryptoError::KeyVersionNotFound(_) |
            CryptoError::KeyGenerationFailed(_) |
            CryptoError::KeyRotationFailed(_) |
            CryptoError::KeyDerivationFailed(_) => ErrorCategory::KeyManagement,
            
            CryptoError::EncryptionFailed(_) |
            CryptoError::DecryptionFailed(_) |
            CryptoError::InvalidCiphertext(_) => ErrorCategory::Encryption,
            
            CryptoError::SigningFailed(_) |
            CryptoError::VerificationFailed(_) |
            CryptoError::InvalidSignature(_) => ErrorCategory::Signing,
            
            CryptoError::InvalidParameter(_) |
            CryptoError::InvalidKeyLength { .. } |
            CryptoError::InvalidNonceLength |
            CryptoError::InvalidAlgorithm(_) => ErrorCategory::Validation,
            
            CryptoError::PolicyViolation(_) |
            CryptoError::PermissionDenied(_) |
            CryptoError::RateLimitExceeded(_) => ErrorCategory::Security,
            
            CryptoError::Internal(_) |
            CryptoError::ConfigurationError(_) |
            CryptoError::NetworkError(_) |
            CryptoError::StorageError(_) => ErrorCategory::System,
            
            _ => ErrorCategory::Other,
        }
    }
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "LOW"),
            ErrorSeverity::Medium => write!(f, "MEDIUM"),
            ErrorSeverity::High => write!(f, "HIGH"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Error categories for monitoring and metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCategory {
    KeyManagement,
    Encryption,
    Signing,
    Validation,
    Security,
    System,
    Other,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::KeyManagement => write!(f, "KEY_MANAGEMENT"),
            ErrorCategory::Encryption => write!(f, "ENCRYPTION"),
            ErrorCategory::Signing => write!(f, "SIGNING"),
            ErrorCategory::Validation => write!(f, "VALIDATION"),
            ErrorCategory::Security => write!(f, "SECURITY"),
            ErrorCategory::System => write!(f, "SYSTEM"),
            ErrorCategory::Other => write!(f, "OTHER"),
        }
    }
}

/// Error context for detailed error reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub operation: String,
    pub key_name: Option<String>,
    pub algorithm: Option<String>,
    pub user: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub request_id: Option<String>,
    pub additional_data: std::collections::HashMap<String, String>,
}

impl ErrorContext {
    pub fn new(operation: String) -> Self {
        Self {
            operation,
            key_name: None,
            algorithm: None,
            user: None,
            timestamp: chrono::Utc::now(),
            request_id: None,
            additional_data: std::collections::HashMap::new(),
        }
    }
    
    pub fn with_key_name(mut self, key_name: String) -> Self {
        self.key_name = Some(key_name);
        self
    }
    
    pub fn with_algorithm(mut self, algorithm: String) -> Self {
        self.algorithm = Some(algorithm);
        self
    }
    
    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }
    
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
    
    pub fn add_data(mut self, key: String, value: String) -> Self {
        self.additional_data.insert(key, value);
        self
    }
}

/// Enhanced error type with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualError {
    pub error: CryptoError,
    pub context: ErrorContext,
}

impl fmt::Display for ContextualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (operation: {}", self.error, self.context.operation)?;
        
        if let Some(ref key_name) = self.context.key_name {
            write!(f, ", key: {}", key_name)?;
        }
        
        if let Some(ref user) = self.context.user {
            write!(f, ", user: {}", user)?;
        }
        
        write!(f, ")")
    }
}

impl std::error::Error for ContextualError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Convert from various error types
impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(err: serde_json::Error) -> Self {
        CryptoError::SerializationError(err.to_string())
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::InvalidParameter(format!("Base64 decode error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_properties() {
        let error = CryptoError::NetworkError("Connection failed".to_string());
        assert!(error.is_recoverable());
        assert!(error.should_retry());
        assert_eq!(error.severity(), ErrorSeverity::Medium);
        assert_eq!(error.category(), ErrorCategory::System);
    }
    
    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("encrypt".to_string())
            .with_key_name("test-key".to_string())
            .with_user("alice".to_string())
            .add_data("size".to_string(), "1024".to_string());
        
        assert_eq!(context.operation, "encrypt");
        assert_eq!(context.key_name, Some("test-key".to_string()));
        assert_eq!(context.user, Some("alice".to_string()));
        assert!(context.additional_data.contains_key("size"));
    }
    
    #[test]
    fn test_contextual_error() {
        let error = CryptoError::EncryptionFailed("Bad key".to_string());
        let context = ErrorContext::new("encrypt".to_string())
            .with_key_name("test-key".to_string());
        
        let contextual_error = ContextualError { error, context };
        let error_string = contextual_error.to_string();
        
        assert!(error_string.contains("Encryption failed"));
        assert!(error_string.contains("operation: encrypt"));
        assert!(error_string.contains("key: test-key"));
    }
}
