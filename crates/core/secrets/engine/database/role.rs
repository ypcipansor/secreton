//! Database role management
//!
//! Provides role-based database credential management with dynamic and static roles.

use chrono::Duration;
use serde::{Deserialize, Serialize};

/// Database role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRole {
    pub db_name: String,
    pub role_type: RoleType,
    pub creation_statements: Vec<String>,
    pub revocation_statements: Vec<String>,
    pub rollback_statements: Vec<String>,
    pub renew_statements: Vec<String>,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub renewable: bool,
}

/// Type of database role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoleType {
    /// Dynamic roles generate new credentials on each request
    Dynamic,
    /// Static roles use a single set of credentials that rotate periodically
    Static {
        username: String,
        rotation_period: Duration,
    },
}

impl DatabaseRole {
    /// Create a new dynamic database role
    pub fn new_dynamic(
        db_name: String,
        creation_statements: Vec<String>,
        revocation_statements: Vec<String>,
    ) -> Self {
        Self {
            db_name,
            role_type: RoleType::Dynamic,
            creation_statements,
            revocation_statements,
            rollback_statements: Vec::new(),
            renew_statements: Vec::new(),
            default_ttl: Duration::hours(1),
            max_ttl: Duration::hours(24),
            renewable: true,
        }
    }

    /// Create a new static database role
    pub fn new_static(
        db_name: String,
        username: String,
        rotation_period: Duration,
        creation_statements: Vec<String>,
        revocation_statements: Vec<String>,
    ) -> Self {
        Self {
            db_name,
            role_type: RoleType::Static {
                username,
                rotation_period,
            },
            creation_statements,
            revocation_statements,
            rollback_statements: Vec::new(),
            renew_statements: Vec::new(),
            default_ttl: Duration::hours(1),
            max_ttl: Duration::hours(24),
            renewable: true,
        }
    }

    /// Set the TTL configuration for the role
    pub fn with_ttl(mut self, default_ttl: Duration, max_ttl: Duration) -> Self {
        self.default_ttl = default_ttl;
        self.max_ttl = max_ttl;
        self
    }

    /// Set renewable flag
    pub fn with_renewable(mut self, renewable: bool) -> Self {
        self.renewable = renewable;
        self
    }

    /// Set rollback statements
    pub fn with_rollback_statements(mut self, statements: Vec<String>) -> Self {
        self.rollback_statements = statements;
        self
    }

    /// Set renew statements
    pub fn with_renew_statements(mut self, statements: Vec<String>) -> Self {
        self.renew_statements = statements;
        self
    }

    /// Check if this role is dynamic
    pub fn is_dynamic(&self) -> bool {
        matches!(self.role_type, RoleType::Dynamic)
    }

    /// Check if this role is static
    pub fn is_static(&self) -> bool {
        matches!(self.role_type, RoleType::Static { .. })
    }

    /// Get the username for static roles
    pub fn get_static_username(&self) -> Option<&str> {
        match &self.role_type {
            RoleType::Static { username, .. } => Some(username),
            RoleType::Dynamic => None,
        }
    }

    /// Get the rotation period for static roles
    pub fn get_rotation_period(&self) -> Option<Duration> {
        match &self.role_type {
            RoleType::Static {
                rotation_period, ..
            } => Some(*rotation_period),
            RoleType::Dynamic => None,
        }
    }

    /// Validate role configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.db_name.is_empty() {
            return Err("Database name cannot be empty".to_string());
        }

        if self.creation_statements.is_empty() {
            return Err("Creation statements cannot be empty".to_string());
        }

        if self.default_ttl > self.max_ttl {
            return Err("Default TTL cannot be greater than max TTL".to_string());
        }

        match &self.role_type {
            RoleType::Static {
                username,
                rotation_period,
            } => {
                if username.is_empty() {
                    return Err("Static role username cannot be empty".to_string());
                }
                if rotation_period.num_seconds() <= 0 {
                    return Err("Rotation period must be positive".to_string());
                }
            }
            RoleType::Dynamic => {
                // No additional validation needed for dynamic roles
            }
        }

        Ok(())
    }
}

/// Pre-defined role templates for common database configurations
pub struct RoleTemplates;

impl RoleTemplates {
    /// PostgreSQL read-only role template
    pub fn postgresql_readonly(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec![
                "CREATE USER \"{{username}}\" WITH PASSWORD '{{password}}';".to_string(),
                "GRANT CONNECT ON DATABASE \"{{database}}\" TO \"{{username}}\";".to_string(),
                "GRANT USAGE ON SCHEMA public TO \"{{username}}\";".to_string(),
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";".to_string(),
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{username}}\";".to_string(),
            ],
            vec![
                "DROP USER IF EXISTS \"{{username}}\";".to_string(),
            ],
        )
    }

    /// PostgreSQL read-write role template
    pub fn postgresql_readwrite(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec![
                "CREATE USER \"{{username}}\" WITH PASSWORD '{{password}}';".to_string(),
                "GRANT CONNECT ON DATABASE \"{{database}}\" TO \"{{username}}\";".to_string(),
                "GRANT USAGE ON SCHEMA public TO \"{{username}}\";".to_string(),
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{username}}\";".to_string(),
                "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO \"{{username}}\";".to_string(),
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{username}}\";".to_string(),
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO \"{{username}}\";".to_string(),
            ],
            vec![
                "DROP USER IF EXISTS \"{{username}}\";".to_string(),
            ],
        )
    }

    /// MySQL read-only role template
    pub fn mysql_readonly(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec![
                "CREATE USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';".to_string(),
                "GRANT SELECT ON `{{database}}`.* TO '{{username}}'@'%';".to_string(),
                "FLUSH PRIVILEGES;".to_string(),
            ],
            vec![
                "DROP USER IF EXISTS '{{username}}'@'%';".to_string(),
                "FLUSH PRIVILEGES;".to_string(),
            ],
        )
    }

    /// MySQL read-write role template
    pub fn mysql_readwrite(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec![
                "CREATE USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';".to_string(),
                "GRANT SELECT, INSERT, UPDATE, DELETE ON `{{database}}`.* TO '{{username}}'@'%';"
                    .to_string(),
                "FLUSH PRIVILEGES;".to_string(),
            ],
            vec![
                "DROP USER IF EXISTS '{{username}}'@'%';".to_string(),
                "FLUSH PRIVILEGES;".to_string(),
            ],
        )
    }

    /// MongoDB read-only role template
    pub fn mongodb_readonly(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec![
                r#"db.createUser({user: "{{username}}", pwd: "{{password}}", roles: [{role: "read", db: "{{database}}"}]})"#.to_string(),
            ],
            vec![
                r#"db.dropUser("{{username}}")"#.to_string(),
            ],
        )
    }

    /// MongoDB read-write role template
    pub fn mongodb_readwrite(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec![
                r#"db.createUser({user: "{{username}}", pwd: "{{password}}", roles: [{role: "readWrite", db: "{{database}}"}]})"#.to_string(),
            ],
            vec![
                r#"db.dropUser("{{username}}")"#.to_string(),
            ],
        )
    }

    /// Redis read-only role template (Redis 6+)
    pub fn redis_readonly(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec!["ACL SETUSER {{username}} on >{{password}} ~* +@read -@dangerous".to_string()],
            vec!["ACL DELUSER {{username}}".to_string()],
        )
    }

    /// Redis read-write role template (Redis 6+)
    pub fn redis_readwrite(db_name: String) -> DatabaseRole {
        DatabaseRole::new_dynamic(
            db_name,
            vec!["ACL SETUSER {{username}} on >{{password}} ~* +@all -@dangerous".to_string()],
            vec!["ACL DELUSER {{username}}".to_string()],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_role_creation() {
        let role = DatabaseRole::new_dynamic(
            "testdb".to_string(),
            vec!["CREATE USER test".to_string()],
            vec!["DROP USER test".to_string()],
        );

        assert!(role.is_dynamic());
        assert!(!role.is_static());
        assert_eq!(role.db_name, "testdb");
        assert_eq!(role.creation_statements.len(), 1);
    }

    #[test]
    fn test_static_role_creation() {
        let role = DatabaseRole::new_static(
            "testdb".to_string(),
            "static_user".to_string(),
            Duration::hours(24),
            vec!["ALTER USER test".to_string()],
            vec!["DROP USER test".to_string()],
        );

        assert!(!role.is_dynamic());
        assert!(role.is_static());
        assert_eq!(role.get_static_username(), Some("static_user"));
        assert_eq!(role.get_rotation_period(), Some(Duration::hours(24)));
    }

    #[test]
    fn test_role_validation() {
        let mut role = DatabaseRole::new_dynamic(
            "testdb".to_string(),
            vec!["CREATE USER test".to_string()],
            vec!["DROP USER test".to_string()],
        );

        assert!(role.validate().is_ok());

        // Test invalid configuration
        role.db_name = "".to_string();
        assert!(role.validate().is_err());
    }

    #[test]
    fn test_role_templates() {
        let role = RoleTemplates::postgresql_readonly("testdb".to_string());
        assert!(role.is_dynamic());
        assert!(!role.creation_statements.is_empty());
        assert!(!role.revocation_statements.is_empty());

        let role = RoleTemplates::mysql_readwrite("testdb".to_string());
        assert!(role.is_dynamic());
        assert!(role.creation_statements.contains(
            &"GRANT SELECT, INSERT, UPDATE, DELETE ON `{{database}}`.* TO '{{username}}'@'%';"
                .to_string()
        ));
    }
}
