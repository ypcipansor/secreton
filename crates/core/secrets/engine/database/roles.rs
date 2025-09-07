//! Database Role Management
//! 
//! Defines role types for database credential management including
//! dynamic roles (temporary credentials) and static roles (managed credentials).

use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::error::SecretonError;

/// Database role types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseRole {
    /// Dynamic role - generates temporary credentials
    Dynamic(DynamicRole),
    /// Static role - manages existing user credentials
    Static(StaticRole),
}

impl DatabaseRole {
    /// Get the database name this role belongs to
    pub fn db_name(&self) -> &str {
        match self {
            DatabaseRole::Dynamic(role) => &role.db_name,
            DatabaseRole::Static(role) => &role.db_name,
        }
    }

    /// Get the role type
    pub fn role_type(&self) -> RoleType {
        match self {
            DatabaseRole::Dynamic(_) => RoleType::Dynamic,
            DatabaseRole::Static(_) => RoleType::Static,
        }
    }

    /// Convert to dynamic role if applicable
    pub fn as_dynamic(&self) -> Option<&DynamicRole> {
        match self {
            DatabaseRole::Dynamic(role) => Some(role),
            _ => None,
        }
    }

    /// Convert to static role if applicable
    pub fn as_static(&self) -> Option<&StaticRole> {
        match self {
            DatabaseRole::Static(role) => Some(role),
            _ => None,
        }
    }

    /// Validate role configuration
    pub fn validate(&self) -> Result<(), SecretonError> {
        match self {
            DatabaseRole::Dynamic(role) => role.validate(),
            DatabaseRole::Static(role) => role.validate(),
        }
    }
}

/// Role type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleType {
    Dynamic,
    Static,
}

/// Dynamic role configuration
/// 
/// Dynamic roles generate temporary database credentials on-demand
/// with automatic expiration and revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicRole {
    /// Database connection name
    pub db_name: String,

    /// Default TTL for generated credentials
    pub default_ttl: Duration,

    /// Maximum TTL for generated credentials
    pub max_ttl: Duration,

    /// SQL statements to create the database user
    pub creation_statements: Vec<String>,

    /// SQL statements to revoke the database user
    pub revocation_statements: Vec<String>,

    /// SQL statements to rollback partially created user
    pub rollback_statements: Vec<String>,

    /// SQL statements to renew user credentials
    pub renew_statements: Vec<String>,

    /// Username template for generated usernames
    /// Supports: {{name}}, {{role_name}}, {{unix_timestamp}}, {{random}}
    pub username_template: String,

    /// Credential type (password, client_certificate)
    pub credential_type: String,

    /// Password policy for generated passwords
    pub password_policy: Option<String>,
}

impl DynamicRole {
    /// Create new dynamic role with defaults
    pub fn new(db_name: String) -> Self {
        Self {
            db_name,
            default_ttl: Duration::from_secs(3600), // 1 hour
            max_ttl: Duration::from_secs(86400),    // 24 hours
            creation_statements: Vec::new(),
            revocation_statements: Vec::new(),
            rollback_statements: Vec::new(),
            renew_statements: Vec::new(),
            username_template: "v_{{role_name}}_{{random}}_{{unix_timestamp}}".to_string(),
            credential_type: "password".to_string(),
            password_policy: None,
        }
    }

    /// Validate dynamic role configuration
    pub fn validate(&self) -> Result<(), SecretonError> {
        if self.db_name.is_empty() {
            return Err(SecretonError::InvalidInput(
                "Database name cannot be empty".to_string()
            ));
        }

        if self.default_ttl.as_secs() == 0 {
            return Err(SecretonError::InvalidInput(
                "Default TTL must be greater than 0".to_string()
            ));
        }

        if self.max_ttl.as_secs() == 0 {
            return Err(SecretonError::InvalidInput(
                "Max TTL must be greater than 0".to_string()
            ));
        }

        if self.default_ttl > self.max_ttl {
            return Err(SecretonError::InvalidInput(
                "Default TTL cannot exceed max TTL".to_string()
            ));
        }

        if self.username_template.is_empty() {
            return Err(SecretonError::InvalidInput(
                "Username template cannot be empty".to_string()
            ));
        }

        // Validate credential type
        match self.credential_type.as_str() {
            "password" | "client_certificate" => {},
            _ => return Err(SecretonError::InvalidInput(
                "Credential type must be 'password' or 'client_certificate'".to_string()
            )),
        }

        Ok(())
    }

    /// Check if role supports given TTL
    pub fn supports_ttl(&self, ttl: Duration) -> bool {
        ttl <= self.max_ttl && ttl.as_secs() > 0
    }

    /// Get effective TTL (capped at max_ttl)
    pub fn effective_ttl(&self, requested_ttl: Option<Duration>) -> Duration {
        match requested_ttl {
            Some(ttl) if ttl <= self.max_ttl => ttl,
            Some(_) => self.max_ttl,
            None => self.default_ttl,
        }
    }
}

/// Static role configuration
/// 
/// Static roles manage existing database users with automatic
/// password rotation on a schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRole {
    /// Database connection name
    pub db_name: String,

    /// Existing database username to manage
    pub username: String,

    /// Current password (managed by Vault)
    pub password: String,

    /// Password rotation period
    pub rotation_period: Duration,

    /// Last rotation timestamp (Unix seconds)
    pub last_rotation: Option<u64>,

    /// SQL statements to rotate password
    pub rotation_statements: Vec<String>,

    /// Credential type (password, client_certificate)
    pub credential_type: String,

    /// Password policy for generated passwords
    pub password_policy: Option<String>,

    /// Skip initial rotation on role creation
    pub skip_import_rotation: bool,
}

impl StaticRole {
    /// Create new static role
    pub fn new(db_name: String, username: String) -> Self {
        Self {
            db_name,
            username,
            password: String::new(),
            rotation_period: Duration::from_secs(86400), // 24 hours
            last_rotation: None,
            rotation_statements: Vec::new(),
            credential_type: "password".to_string(),
            password_policy: None,
            skip_import_rotation: false,
        }
    }

    /// Validate static role configuration
    pub fn validate(&self) -> Result<(), SecretonError> {
        if self.db_name.is_empty() {
            return Err(SecretonError::InvalidInput(
                "Database name cannot be empty".to_string()
            ));
        }

        if self.username.is_empty() {
            return Err(SecretonError::InvalidInput(
                "Username cannot be empty".to_string()
            ));
        }

        if self.rotation_period.as_secs() == 0 {
            return Err(SecretonError::InvalidInput(
                "Rotation period must be greater than 0".to_string()
            ));
        }

        // Validate credential type
        match self.credential_type.as_str() {
            "password" | "client_certificate" => {},
            _ => return Err(SecretonError::InvalidInput(
                "Credential type must be 'password' or 'client_certificate'".to_string()
            )),
        }

        Ok(())
    }

    /// Check if rotation is due
    pub fn is_rotation_due(&self) -> bool {
        match self.last_rotation {
            Some(last) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                
                now - last >= self.rotation_period.as_secs()
            }
            None => true, // Never rotated, so due for rotation
        }
    }

    /// Get next rotation time
    pub fn next_rotation_time(&self) -> Option<u64> {
        self.last_rotation.map(|last| last + self.rotation_period.as_secs())
    }

    /// Calculate TTL until next rotation
    pub fn ttl_until_rotation(&self) -> Duration {
        match self.next_rotation_time() {
            Some(next) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                
                if next > now {
                    Duration::from_secs(next - now)
                } else {
                    Duration::from_secs(0) // Overdue
                }
            }
            None => Duration::from_secs(0), // Never rotated
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_role_creation() {
        let role = DynamicRole::new("test-db".to_string());
        
        assert_eq!(role.db_name, "test-db");
        assert_eq!(role.default_ttl, Duration::from_secs(3600));
        assert_eq!(role.max_ttl, Duration::from_secs(86400));
        assert_eq!(role.credential_type, "password");
        assert!(!role.username_template.is_empty());
    }

    #[test]
    fn test_dynamic_role_validation() {
        let mut role = DynamicRole::new("test-db".to_string());
        
        // Valid role should pass
        assert!(role.validate().is_ok());
        
        // Empty db_name should fail
        role.db_name = String::new();
        assert!(role.validate().is_err());
        
        role.db_name = "test-db".to_string();
        
        // Zero TTL should fail
        role.default_ttl = Duration::from_secs(0);
        assert!(role.validate().is_err());
        
        role.default_ttl = Duration::from_secs(3600);
        
        // default_ttl > max_ttl should fail
        role.default_ttl = Duration::from_secs(86400);
        role.max_ttl = Duration::from_secs(3600);
        assert!(role.validate().is_err());
        
        // Invalid credential type should fail
        role.max_ttl = Duration::from_secs(86400);
        role.credential_type = "invalid".to_string();
        assert!(role.validate().is_err());
    }

    #[test]
    fn test_dynamic_role_ttl_support() {
        let role = DynamicRole::new("test-db".to_string());
        
        assert!(role.supports_ttl(Duration::from_secs(1800))); // 30 minutes
        assert!(role.supports_ttl(Duration::from_secs(86400))); // 24 hours (max)
        assert!(!role.supports_ttl(Duration::from_secs(172800))); // 48 hours (over max)
        assert!(!role.supports_ttl(Duration::from_secs(0))); // Zero
    }

    #[test]
    fn test_dynamic_role_effective_ttl() {
        let role = DynamicRole::new("test-db".to_string());
        
        // No request = default
        assert_eq!(role.effective_ttl(None), Duration::from_secs(3600));
        
        // Within limits = requested
        assert_eq!(role.effective_ttl(Some(Duration::from_secs(1800))), Duration::from_secs(1800));
        
        // Over max = max
        assert_eq!(role.effective_ttl(Some(Duration::from_secs(172800))), Duration::from_secs(86400));
    }

    #[test]
    fn test_static_role_creation() {
        let role = StaticRole::new("test-db".to_string(), "testuser".to_string());
        
        assert_eq!(role.db_name, "test-db");
        assert_eq!(role.username, "testuser");
        assert_eq!(role.rotation_period, Duration::from_secs(86400));
        assert_eq!(role.credential_type, "password");
        assert_eq!(role.last_rotation, None);
    }

    #[test]
    fn test_static_role_validation() {
        let mut role = StaticRole::new("test-db".to_string(), "testuser".to_string());
        
        // Valid role should pass
        assert!(role.validate().is_ok());
        
        // Empty db_name should fail
        role.db_name = String::new();
        assert!(role.validate().is_err());
        
        role.db_name = "test-db".to_string();
        
        // Empty username should fail
        role.username = String::new();
        assert!(role.validate().is_err());
        
        role.username = "testuser".to_string();
        
        // Zero rotation period should fail
        role.rotation_period = Duration::from_secs(0);
        assert!(role.validate().is_err());
    }

    #[test]
    fn test_static_role_rotation_due() {
        let mut role = StaticRole::new("test-db".to_string(), "testuser".to_string());
        
        // Never rotated should be due
        assert!(role.is_rotation_due());
        
        // Recently rotated should not be due
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        role.last_rotation = Some(now);
        assert!(!role.is_rotation_due());
        
        // Old rotation should be due
        role.last_rotation = Some(now - 172800); // 2 days ago
        assert!(role.is_rotation_due());
    }

    #[test]
    fn test_database_role_enum() {
        let dynamic = DatabaseRole::Dynamic(DynamicRole::new("test-db".to_string()));
        let static_role = DatabaseRole::Static(StaticRole::new("test-db".to_string(), "testuser".to_string()));
        
        assert_eq!(dynamic.db_name(), "test-db");
        assert_eq!(static_role.db_name(), "test-db");
        
        assert_eq!(dynamic.role_type(), RoleType::Dynamic);
        assert_eq!(static_role.role_type(), RoleType::Static);
        
        assert!(dynamic.as_dynamic().is_some());
        assert!(dynamic.as_static().is_none());
        
        assert!(static_role.as_static().is_some());
        assert!(static_role.as_dynamic().is_none());
    }
}
