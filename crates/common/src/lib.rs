//! # Secreton Common
//!
//! Common types and utilities shared across all Secreton crates.
//! Provides foundational abstractions for security levels, error handling,
//! and common data structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod models;
pub mod dto;

/// Security classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum SecurityLevel {
    /// Public information - no security controls required
    Public = 0,

    /// Internal use - basic access controls
    #[default]
    Internal = 1,

    /// Confidential - restricted access
    Confidential = 2,

    /// Secret - highly restricted access
    Secret = 3,

    /// Top Secret - maximum security controls
    TopSecret = 4,
}

use std::str::FromStr;

/// Basic error types for common crate
#[derive(Debug, thiserror::Error)]
pub enum CommonError {
    #[error("Validation error: {message}")]
    Validation { message: String },
    #[error("Parse error: {message}")]
    Parse { message: String },
    #[error("Not found error: {message}")]
    NotFound { message: String },
    #[error("Cryptographic error: {message}")]
    Cryptographic { message: String },
}

impl From<String> for CommonError {
    fn from(message: String) -> Self {
        CommonError::Validation { message }
    }
}

impl SecurityLevel {
    /// Get security level name
    pub fn name(&self) -> &'static str {
        match self {
            SecurityLevel::Public => "Public",
            SecurityLevel::Internal => "Internal",
            SecurityLevel::Confidential => "Confidential",
            SecurityLevel::Secret => "Secret",
            SecurityLevel::TopSecret => "Top Secret",
        }
    }

    /// Get security level from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace("-", "_").as_str() {
            "public" => Some(SecurityLevel::Public),
            "internal" => Some(SecurityLevel::Internal),
            "confidential" => Some(SecurityLevel::Confidential),
            "secret" => Some(SecurityLevel::Secret),
            "top_secret" => Some(SecurityLevel::TopSecret),
            _ => None,
        }
    }

    /// Parse security level from string (alias for from_str)
    pub fn parse(s: &str) -> Option<Self> {
        Self::from_str(s)
    }

    /// Check if this security level can access another level
    /// Higher security levels can access lower ones, but not vice versa
    pub fn can_access(&self, other: SecurityLevel) -> bool {
        *self >= other
    }
}

impl FromStr for SecurityLevel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_str(s).ok_or_else(|| format!("Invalid security level: {}", s))
    }
}

/// Common result type for operations
pub type Result<T> = std::result::Result<T, CommonError>;

/// Service initialization result
pub type InitResult<T> = std::result::Result<T, ServiceInitError>;

/// Common HTTP response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the operation was successful
    pub success: bool,
    /// Response data (if successful)
    pub data: Option<T>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            metadata: HashMap::new(),
        }
    }

    /// Create a successful response with metadata
    pub fn success_with_metadata(data: T, metadata: HashMap<String, serde_json::Value>) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            metadata,
        }
    }

    /// Create an error response
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            metadata: HashMap::new(),
        }
    }

    /// Create an error response with metadata
    pub fn error_with_metadata(
        message: impl Into<String>,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            metadata,
        }
    }
}

/// Pagination parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Page number (1-based)
    pub page: Option<u32>,
    /// Number of items per page
    pub limit: Option<u32>,
    /// Sort field
    pub sort_by: Option<String>,
    /// Sort order
    pub sort_order: Option<String>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            limit: Some(50),
            sort_by: None,
            sort_order: Some("asc".to_string()),
        }
    }
}

/// Query parameters for list operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueryParams {
    /// Pagination parameters
    pub pagination: PaginationParams,
    /// Filter criteria
    pub filters: HashMap<String, String>,
    /// Search query
    pub search: Option<String>,
}

/// Common trait for entities with timestamps
pub trait Timestamped {
    /// Get creation timestamp
    fn created_at(&self) -> chrono::DateTime<chrono::Utc>;

    /// Get last update timestamp
    fn updated_at(&self) -> chrono::DateTime<chrono::Utc>;

    /// Check if entity is expired
    fn is_expired(&self) -> bool {
        self.updated_at() < chrono::Utc::now()
    }
}

/// Common trait for entities with unique IDs
pub trait Identifiable {
    /// Get the unique identifier
    fn id(&self) -> &str;

    /// Set the unique identifier
    fn set_id(&mut self, id: String);
}

/// Common trait for versioned entities
pub trait Versioned {
    /// Get the current version
    fn version(&self) -> u32;

    /// Increment version
    fn increment_version(&mut self);
}

/// Common trait for entities that can be validated
pub trait Validatable {
    /// Validate the entity
    fn validate(&self) -> Result<()>;
}

/// Common trait for auditable operations
#[async_trait::async_trait]
pub trait Auditable {
    /// Get audit trail for this entity
    async fn audit_trail(&self) -> Result<Vec<AuditEvent>>;
}

/// Audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event ID
    pub id: String,
    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event type
    pub event_type: String,
    /// User who performed the action
    pub user: String,
    /// Resource affected
    pub resource: String,
    /// Action performed
    pub action: String,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Common trait for cacheable entities
#[async_trait::async_trait]
pub trait Cacheable {
    /// Cache key for this entity
    fn cache_key(&self) -> String;

    /// Time-to-live for cache
    fn ttl(&self) -> Option<std::time::Duration>;
}

/// Common trait for encryptable data
pub trait Encryptable {
    /// Encrypt the data
    fn encrypt(&mut self, key: &[u8]) -> Result<()>;

    /// Decrypt the data
    fn decrypt(&mut self, key: &[u8]) -> Result<()>;

    /// Check if data is encrypted
    fn is_encrypted(&self) -> bool;
}

/// Common trait for serializable entities
pub trait Serializable {
    /// Serialize to bytes
    fn to_bytes(&self) -> Result<Vec<u8>>;

    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// Utility functions for common operations
pub mod utils {
    use super::*;

    /// Generate a random UUID v4
    pub fn generate_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Get current timestamp
    pub fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    /// Password generation utilities
    pub mod password {
        use rand::Rng;

        /// Generate a secure random password with the specified length
        /// Uses a charset containing uppercase, lowercase, numbers, and special characters
        pub fn generate_password(length: usize) -> String {
            const CHARSET: &[u8] =
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
            let mut rng = rand::thread_rng();

            (0..length)
                .map(|_| {
                    let idx = rng.gen_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect()
        }

        /// Generate a password that meets the specified policy requirements
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct PasswordPolicy {
            pub min_length: usize,
            pub max_length: Option<usize>,
            pub require_uppercase: bool,
            pub require_lowercase: bool,
            pub require_numbers: bool,
            pub require_special: bool,
            pub allowed_special_chars: Option<String>,
        }

        impl Default for PasswordPolicy {
            fn default() -> Self {
                Self {
                    min_length: 12,
                    max_length: Some(32),
                    require_uppercase: true,
                    require_lowercase: true,
                    require_numbers: true,
                    require_special: true,
                    allowed_special_chars: Some("!@#$%^&*".to_string()),
                }
            }
        }

        impl PasswordPolicy {
            /// Create a policy with custom length
            pub fn with_length(min_length: usize) -> Self {
                Self {
                    min_length,
                    ..Default::default()
                }
            }

            /// Create a policy with length range
            pub fn with_length_range(min_length: usize, max_length: usize) -> Self {
                Self {
                    min_length,
                    max_length: Some(max_length),
                    ..Default::default()
                }
            }

            /// Validate the password policy
            pub fn validate(&self) -> crate::Result<()> {
                if self.min_length == 0 {
                    return Err(crate::CommonError::Validation {
                        message: "Minimum password length cannot be zero".to_string(),
                    });
                }

                if let Some(max_len) = self.max_length
                    && max_len < self.min_length
                {
                    return Err(crate::CommonError::Validation {
                        message: "Maximum password length cannot be less than minimum length"
                            .to_string(),
                    });
                }

                Ok(())
            }
        }

        pub fn generate_password_with_policy(policy: &PasswordPolicy) -> String {
            let mut password = String::new();
            let mut rng = rand::thread_rng();

            // Ensure minimum requirements are met
            if policy.require_lowercase {
                const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
                let idx = rng.gen_range(0..LOWER.len());
                password.push(LOWER[idx] as char);
            }

            if policy.require_uppercase {
                const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                let idx = rng.gen_range(0..UPPER.len());
                password.push(UPPER[idx] as char);
            }

            if policy.require_numbers {
                const NUMBERS: &[u8] = b"0123456789";
                let idx = rng.gen_range(0..NUMBERS.len());
                password.push(NUMBERS[idx] as char);
            }

            if policy.require_special {
                let special_chars = policy
                    .allowed_special_chars
                    .as_deref()
                    .unwrap_or("!@#$%^&*");
                let chars: Vec<char> = special_chars.chars().collect();
                let idx = rng.gen_range(0..chars.len());
                password.push(chars[idx]);
            }

            // Fill the rest with random characters from full charset
            let mut charset =
                String::from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
            if policy.require_special {
                if let Some(special) = &policy.allowed_special_chars {
                    charset.push_str(special);
                } else {
                    charset.push_str("!@#$%^&*");
                }
            }

            let chars: Vec<char> = charset.chars().collect();
            while password.len() < policy.min_length {
                let idx = rng.gen_range(0..chars.len());
                password.push(chars[idx]);
            }

            // Apply max length if specified
            if let Some(max_len) = policy.max_length
                && password.len() > max_len
            {
                password = password[..max_len].to_string();
            }

            // Shuffle the password for better randomness
            let mut chars: Vec<char> = password.chars().collect();
            for i in (1..chars.len()).rev() {
                let j = rng.gen_range(0..=i);
                chars.swap(i, j);
            }

            chars.into_iter().collect()
        }
    }

    /// Validate email format
    pub fn is_valid_email(email: &str) -> bool {
        email.contains('@') && email.contains('.')
    }

    /// Sanitize string for safe storage
    pub fn sanitize_string(input: &str) -> String {
        input
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace())
            .collect()
    }

    /// Create a standardized error response
    pub fn error_response<T>(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::error(message)
    }

    /// Create a standardized success response
    pub fn success_response<T>(data: T) -> ApiResponse<T> {
        ApiResponse::success(data)
    }
}

/// Password generation utilities
pub mod password_legacy {
    use super::*;
    /// Generate a secure random password (legacy function - use utils::password::generate_password instead)
    pub fn generate_password() -> Result<String> {
        Ok(utils::password::generate_password(32))
    }
}
pub use password_legacy::generate_password;

/// Service health status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceHealth {
    Healthy,
    Unhealthy(String),
    Degraded(String),
}

/// Service initialization error
#[derive(Debug, thiserror::Error)]
pub enum ServiceInitError {
    #[error("Service initialization failed: {message}")]
    InitializationFailed { message: String },
    #[error("Service dependency missing: {dependency}")]
    DependencyMissing { dependency: String },
    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },
}

/// Service result type
pub type ServiceResult<T> = std::result::Result<T, ServiceInitError>;

/// Standard service trait for all services in the system
#[async_trait::async_trait]
pub trait Service {
    async fn start(&self) -> ServiceResult<()>;
    async fn stop(&self) -> ServiceResult<()>;
    async fn health(&self) -> ServiceResult<ServiceHealth>;
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn uptime_seconds(&self) -> u64;
}

/// Service container trait for dependency injection
#[async_trait::async_trait]
pub trait ServiceContainer {
    async fn initialize(&mut self) -> InitResult<()>;
    async fn start_services(&self) -> InitResult<()>;
    async fn stop_services(&self) -> InitResult<()>;
    async fn health_check(&self) -> InitResult<ServiceHealth>;
    fn get_service<T: 'static>(&self, name: &str) -> Option<&T>;
    fn register_service<T: 'static + Send + Sync>(&mut self, name: String, service: T);
}

/// Standard service container implementation
pub struct StandardServiceContainer {
    services: std::collections::HashMap<String, Box<dyn std::any::Any + Send + Sync>>,
}

impl Default for StandardServiceContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardServiceContainer {
    pub fn new() -> Self {
        Self {
            services: std::collections::HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl ServiceContainer for StandardServiceContainer {
    async fn initialize(&mut self) -> InitResult<()> {
        Ok(())
    }

    async fn start_services(&self) -> InitResult<()> {
        Ok(())
    }

    async fn stop_services(&self) -> InitResult<()> {
        Ok(())
    }

    async fn health_check(&self) -> InitResult<ServiceHealth> {
        Ok(ServiceHealth::Healthy)
    }

    fn get_service<T: 'static>(&self, name: &str) -> Option<&T> {
        self.services.get(name)?.downcast_ref::<T>()
    }

    fn register_service<T: 'static + Send + Sync>(&mut self, name: String, service: T) {
        self.services.insert(name, Box::new(service));
    }
}

/// CRUD service trait for entities with standard operations
#[async_trait::async_trait]
pub trait CrudService<T> {
    async fn create(&self, entity: T) -> Result<T>;
    async fn get(&self, id: &str) -> Result<T>;
    async fn update(&self, id: &str, entity: T) -> Result<T>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn list(&self, params: ListParams) -> Result<PaginatedResponse<T>>;
}

/// Parameters for list operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListParams {
    pub pagination: PaginationParams,
    pub filters: std::collections::HashMap<String, String>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            pagination: PaginationParams::default(),
            filters: std::collections::HashMap::new(),
            search: None,
            sort_by: None,
            sort_order: Some("asc".to_string()),
        }
    }
}

/// Paginated response for list operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    pub has_more: bool,
}

/// Password generation utilities
pub use utils::password;
