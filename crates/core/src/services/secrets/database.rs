//! Database Secrets Engine
//!
//! Dynamically generates database credentials with automatic rotation.
//! Supports MySQL, PostgreSQL, MongoDB and other databases.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Error types for database secrets engine
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Database role not found: {0}")]
    RoleNotFound(String),

    #[error("Credential generation failed: {0}")]
    CredentialGenerationFailed(String),

    #[error("Rotation failed: {0}")]
    RotationFailed(String),

    #[error("Revocation failed: {0}")]
    RevocationFailed(String),

    #[error("Unsupported database type: {0}")]
    UnsupportedDatabase(String),
}

/// Database type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MongoDB,
    Redis,
    Cassandra,
    MSSQL,
}

impl DatabaseType {
    pub fn as_str(&self) -> &str {
        match self {
            DatabaseType::MySQL => "mysql",
            DatabaseType::PostgreSQL => "postgresql",
            DatabaseType::MongoDB => "mongodb",
            DatabaseType::Redis => "redis",
            DatabaseType::Cassandra => "cassandra",
            DatabaseType::MSSQL => "mssql",
        }
    }
}

/// Database connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConnection {
    /// Connection name
    pub name: String,

    /// Database type
    pub db_type: DatabaseType,

    /// Connection URL
    pub connection_url: String,

    /// Maximum open connections
    pub max_open_connections: u32,

    /// Maximum idle connections
    pub max_idle_connections: u32,

    /// Connection max lifetime in seconds
    pub max_connection_lifetime: u32,

    /// Verify connection on startup
    pub verify_connection: bool,

    /// Root rotation statements
    pub root_rotation_statements: Vec<String>,

    /// Root credentials
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for DatabaseConnection {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            db_type: DatabaseType::PostgreSQL,
            connection_url: String::new(),
            max_open_connections: 4,
            max_idle_connections: 2,
            max_connection_lifetime: 3600,
            verify_connection: true,
            root_rotation_statements: Vec::new(),
            username: None,
            password: None,
        }
    }
}

/// Database role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRole {
    /// Role name
    pub name: String,

    /// Database connection name
    pub db_name: String,

    /// Default TTL for credentials
    pub default_ttl: u32,

    /// Maximum TTL for credentials
    pub max_ttl: u32,

    /// Creation statements (SQL/commands to create user)
    pub creation_statements: Vec<String>,

    /// Revocation statements (SQL/commands to revoke/delete user)
    pub revocation_statements: Vec<String>,

    /// Rotation statements (SQL/commands to rotate password)
    pub rotation_statements: Vec<String>,

    /// Renew statements (SQL/commands executed on lease renewal)
    pub renew_statements: Vec<String>,
}

impl Default for DatabaseRole {
    fn default() -> Self {
        Self {
            name: String::new(),
            db_name: String::new(),
            default_ttl: 3600,
            max_ttl: 86400,
            creation_statements: Vec::new(),
            revocation_statements: Vec::new(),
            rotation_statements: Vec::new(),
            renew_statements: Vec::new(),
        }
    }
}

/// Generated database credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCredentials {
    /// Unique credential ID
    pub id: String,

    /// Database username
    pub username: String,

    /// Database password
    pub password: String,

    /// Connection string (optional)
    pub connection_url: Option<String>,

    /// Creation time
    pub created_at: DateTime<Utc>,

    /// Expiration time
    pub expires_at: DateTime<Utc>,

    /// Role name used
    pub role_name: String,

    /// Database name
    pub db_name: String,
}

/// Database secrets engine
pub struct DatabaseSecretsEngine {
    connections: Arc<RwLock<HashMap<String, DatabaseConnection>>>,
    roles: Arc<RwLock<HashMap<String, DatabaseRole>>>,
    active_credentials: Arc<RwLock<HashMap<String, DatabaseCredentials>>>,
}

impl DatabaseSecretsEngine {
    /// Create new database secrets engine
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            active_credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure database connection
    pub async fn configure_connection(
        &self,
        config: DatabaseConnection,
    ) -> Result<(), DatabaseError> {
        // Validate configuration
        if config.name.is_empty() {
            return Err(DatabaseError::InvalidConfig(
                "Connection name cannot be empty".to_string(),
            ));
        }
        if config.connection_url.is_empty() {
            return Err(DatabaseError::InvalidConfig(
                "Connection URL cannot be empty".to_string(),
            ));
        }

        // Test connection if requested
        if config.verify_connection {
            self.test_connection(&config).await?;
        }

        // Store connection
        let mut connections = self.connections.write().await;
        connections.insert(config.name.clone(), config);

        Ok(())
    }

    /// Test database connection
    async fn test_connection(&self, config: &DatabaseConnection) -> Result<(), DatabaseError> {
        // In production, this would actually test the connection
        // For now, just validate URL format
        if !config.connection_url.contains("://") {
            return Err(DatabaseError::ConnectionError(
                "Invalid connection URL format".to_string(),
            ));
        }
        Ok(())
    }

    /// Create database role
    pub async fn create_role(&self, role: DatabaseRole) -> Result<(), DatabaseError> {
        // Validate role
        if role.name.is_empty() {
            return Err(DatabaseError::InvalidConfig(
                "Role name cannot be empty".to_string(),
            ));
        }
        if role.creation_statements.is_empty() {
            return Err(DatabaseError::InvalidConfig(
                "Creation statements required".to_string(),
            ));
        }

        // Verify database connection exists
        let connections = self.connections.read().await;
        if !connections.contains_key(&role.db_name) {
            return Err(DatabaseError::InvalidConfig(format!(
                "Database connection '{}' not found",
                role.db_name
            )));
        }
        drop(connections);

        // Store role
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials for a role
    pub async fn generate_credentials(
        &self,
        role_name: &str,
        ttl: Option<u32>,
    ) -> Result<DatabaseCredentials, DatabaseError> {
        // Get role
        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| DatabaseError::RoleNotFound(role_name.to_string()))?
            .clone();
        drop(roles);

        // Get connection
        let connections = self.connections.read().await;
        let connection = connections
            .get(&role.db_name)
            .ok_or_else(|| {
                DatabaseError::InvalidConfig(format!(
                    "Database connection '{}' not found",
                    role.db_name
                ))
            })?
            .clone();
        drop(connections);

        // Determine TTL
        let ttl = ttl.unwrap_or(role.default_ttl);
        if ttl > role.max_ttl {
            return Err(DatabaseError::InvalidConfig(format!(
                "TTL {} exceeds maximum {}",
                ttl, role.max_ttl
            )));
        }

        // Generate username and password
        let username = self.generate_username(&connection.db_type, role_name);
        let password = self.generate_password(32);

        // Execute creation statements
        self.execute_creation_statements(
            &connection,
            &role.creation_statements,
            &username,
            &password,
        )
        .await?;

        // Create credentials record
        let now = Utc::now();
        let credentials = DatabaseCredentials {
            id: Uuid::new_v4().to_string(),
            username: username.clone(),
            password: password.clone(),
            connection_url: Some(self.build_connection_url(&connection, &username, &password)),
            created_at: now,
            expires_at: now + Duration::seconds(ttl as i64),
            role_name: role_name.to_string(),
            db_name: role.db_name.clone(),
        };

        // Store active credentials
        let mut active = self.active_credentials.write().await;
        active.insert(credentials.id.clone(), credentials.clone());

        Ok(credentials)
    }

    /// Generate database username
    fn generate_username(&self, db_type: &DatabaseType, role_name: &str) -> String {
        let uuid = Uuid::new_v4().to_string();
        let short_uuid = &uuid[..8];

        match db_type {
            DatabaseType::MySQL | DatabaseType::PostgreSQL => {
                format!("v-{}-{}", role_name, short_uuid)
            }
            DatabaseType::MongoDB => {
                format!("v_{}_{}", role_name.replace("-", "_"), short_uuid)
            }
            _ => format!("vault_{}_{}", role_name, short_uuid),
        }
    }

    /// Generate secure random password
    fn generate_password(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                !@#$%^&*";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Execute creation statements
    async fn execute_creation_statements(
        &self,
        connection: &DatabaseConnection,
        statements: &[String],
        username: &str,
        password: &str,
    ) -> Result<(), DatabaseError> {
        // In production, this would execute actual SQL/commands
        // For now, validate that placeholders exist
        for stmt in statements {
            if !stmt.contains("{{username}}") && !stmt.contains("{{password}}") {
                return Err(DatabaseError::CredentialGenerationFailed(
                    "Creation statements must contain {{username}} or {{password}} placeholders"
                        .to_string(),
                ));
            }
        }

        // Simulate execution
        Ok(())
    }

    /// Build connection URL with credentials
    fn build_connection_url(
        &self,
        connection: &DatabaseConnection,
        username: &str,
        password: &str,
    ) -> String {
        // Simple URL building (production would be more sophisticated)
        let url = &connection.connection_url;

        if url.contains("@") {
            // Replace existing credentials
            url.clone()
        } else {
            // Insert credentials
            if let Some(pos) = url.find("://") {
                format!(
                    "{}://{}:{}@{}",
                    &url[..pos],
                    username,
                    password,
                    &url[pos + 3..]
                )
            } else {
                url.clone()
            }
        }
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, credential_id: &str) -> Result<(), DatabaseError> {
        // Get credentials
        let mut active = self.active_credentials.write().await;
        let credentials = active.remove(credential_id).ok_or_else(|| {
            DatabaseError::RevocationFailed(format!("Credentials {} not found", credential_id))
        })?;
        drop(active);

        // Get role and connection
        let roles = self.roles.read().await;
        let role = roles
            .get(&credentials.role_name)
            .ok_or_else(|| DatabaseError::RoleNotFound(credentials.role_name.clone()))?
            .clone();
        drop(roles);

        let connections = self.connections.read().await;
        let connection = connections
            .get(&role.db_name)
            .ok_or_else(|| {
                DatabaseError::InvalidConfig(format!(
                    "Database connection '{}' not found",
                    role.db_name
                ))
            })?
            .clone();
        drop(connections);

        // Execute revocation statements
        self.execute_revocation_statements(
            &connection,
            &role.revocation_statements,
            &credentials.username,
        )
        .await?;

        Ok(())
    }

    /// Execute revocation statements
    async fn execute_revocation_statements(
        &self,
        _connection: &DatabaseConnection,
        statements: &[String],
        username: &str,
    ) -> Result<(), DatabaseError> {
        // In production, this would execute actual revocation
        // For now, just validate
        if statements.is_empty() {
            return Err(DatabaseError::RevocationFailed(
                "No revocation statements configured".to_string(),
            ));
        }

        Ok(())
    }

    /// List active credentials
    pub async fn list_credentials(&self) -> Vec<DatabaseCredentials> {
        let active = self.active_credentials.read().await;
        active.values().cloned().collect()
    }

    /// Rotate root credentials
    pub async fn rotate_root(&self, connection_name: &str) -> Result<(), DatabaseError> {
        let connections = self.connections.read().await;
        let connection = connections.get(connection_name).ok_or_else(|| {
            DatabaseError::InvalidConfig(format!("Connection '{}' not found", connection_name))
        })?;

        if connection.root_rotation_statements.is_empty() {
            return Err(DatabaseError::RotationFailed(
                "No root rotation statements configured".to_string(),
            ));
        }

        // In production, would execute rotation and update stored credentials
        Ok(())
    }
}

impl Default for DatabaseSecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_engine_creation() {
        let engine = DatabaseSecretsEngine::new();
        assert_eq!(engine.list_credentials().await.len(), 0);
    }

    #[tokio::test]
    async fn test_configure_connection() {
        let engine = DatabaseSecretsEngine::new();

        let config = DatabaseConnection {
            name: "test-db".to_string(),
            db_type: DatabaseType::PostgreSQL,
            connection_url: "postgresql://localhost:5432/testdb".to_string(),
            verify_connection: false,
            ..Default::default()
        };

        let result = engine.configure_connection(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_role() {
        let engine = DatabaseSecretsEngine::new();

        // First configure connection
        let config = DatabaseConnection {
            name: "test-db".to_string(),
            db_type: DatabaseType::PostgreSQL,
            connection_url: "postgresql://localhost:5432/testdb".to_string(),
            verify_connection: false,
            ..Default::default()
        };
        engine.configure_connection(config).await.unwrap();

        // Create role
        let role = DatabaseRole {
            name: "readonly".to_string(),
            db_name: "test-db".to_string(),
            default_ttl: 3600,
            max_ttl: 86400,
            creation_statements: vec![
                "CREATE USER '{{username}}'@'%' IDENTIFIED BY '{{password}}'".to_string(),
                "GRANT SELECT ON *.* TO '{{username}}'@'%'".to_string(),
            ],
            revocation_statements: vec!["DROP USER '{{username}}'@'%'".to_string()],
            ..Default::default()
        };

        let result = engine.create_role(role).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_credentials() {
        let engine = DatabaseSecretsEngine::new();

        // Setup connection and role
        let config = DatabaseConnection {
            name: "test-db".to_string(),
            db_type: DatabaseType::PostgreSQL,
            connection_url: "postgresql://localhost:5432/testdb".to_string(),
            verify_connection: false,
            ..Default::default()
        };
        engine.configure_connection(config).await.unwrap();

        let role = DatabaseRole {
            name: "readonly".to_string(),
            db_name: "test-db".to_string(),
            default_ttl: 3600,
            max_ttl: 86400,
            creation_statements: vec![
                "CREATE USER '{{username}}'@'%' IDENTIFIED BY '{{password}}'".to_string(),
            ],
            revocation_statements: vec!["DROP USER '{{username}}'@'%'".to_string()],
            ..Default::default()
        };
        engine.create_role(role).await.unwrap();

        // Generate credentials
        let result = engine.generate_credentials("readonly", Some(1800)).await;
        assert!(result.is_ok());

        let creds = result.unwrap();
        assert!(creds.username.starts_with("v-readonly-"));
        assert_eq!(creds.password.len(), 32);
        assert_eq!(creds.role_name, "readonly");
    }

    #[tokio::test]
    async fn test_password_generation() {
        let engine = DatabaseSecretsEngine::new();

        let password1 = engine.generate_password(32);
        let password2 = engine.generate_password(32);

        assert_eq!(password1.len(), 32);
        assert_eq!(password2.len(), 32);
        assert_ne!(password1, password2); // Should be different
    }
}
