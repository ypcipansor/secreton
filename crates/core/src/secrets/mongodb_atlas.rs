// MongoDB Atlas Secrets Engine - Dynamic MongoDB Atlas database user generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum MongoDBAtlasError {
    #[error("MongoDB Atlas error: {0}")]
    AtlasError(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("API error: {0}")]
    APIError(String),
}

pub type Result<T> = std::result::Result<T, MongoDBAtlasError>;

/// MongoDB Atlas configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoDBAtlasConfig {
    pub public_key: String,  // Atlas API public key
    pub private_key: String, // Atlas API private key
    pub project_id: String,  // Atlas project ID
}

/// Database role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRole {
    pub role_name: String,               // Built-in role or custom role
    pub database_name: String,           // Database for the role
    pub collection_name: Option<String>, // Optional collection scope
}

/// MongoDB Atlas role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasRole {
    pub name: String,
    pub project_id: String,
    pub database_name: String,    // Default database
    pub roles: Vec<DatabaseRole>, // Roles to assign
    pub scopes: Vec<String>,      // Resource scopes (cluster names)
    pub ttl: Duration,            // User TTL
}

/// Generated MongoDB Atlas user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasUser {
    pub username: String,
    pub password: String,
    pub database_name: String,
    pub roles: Vec<DatabaseRole>,
    pub scopes: Vec<String>,
    pub project_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// MongoDB Atlas secrets engine
pub struct MongoDBAtlasEngine {
    config: Arc<RwLock<Option<MongoDBAtlasConfig>>>,
    roles: Arc<RwLock<HashMap<String, AtlasRole>>>,
    users: Arc<RwLock<HashMap<String, AtlasUser>>>,
}

impl MongoDBAtlasEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure MongoDB Atlas connection
    pub async fn configure(&self, config: MongoDBAtlasConfig) -> Result<()> {
        if config.public_key.is_empty() {
            return Err(MongoDBAtlasError::ConfigError(
                "Public key is required".to_string(),
            ));
        }
        if config.private_key.is_empty() {
            return Err(MongoDBAtlasError::ConfigError(
                "Private key is required".to_string(),
            ));
        }
        if config.project_id.is_empty() {
            return Err(MongoDBAtlasError::ConfigError(
                "Project ID is required".to_string(),
            ));
        }

        // Validate API credentials (mock)
        self.validate_credentials(&config).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Validate Atlas API credentials
    async fn validate_credentials(&self, _config: &MongoDBAtlasConfig) -> Result<()> {
        // Mock validation
        // Real implementation would:
        // 1. Call Atlas API to verify credentials
        // 2. Check project access
        // 3. Verify permissions to manage database users
        Ok(())
    }

    /// Create a role
    pub async fn create_role(&self, role: AtlasRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(MongoDBAtlasError::ConfigError(
                "Role name is required".to_string(),
            ));
        }
        if role.database_name.is_empty() {
            return Err(MongoDBAtlasError::ConfigError(
                "Database name is required".to_string(),
            ));
        }
        if role.roles.is_empty() {
            return Err(MongoDBAtlasError::ConfigError(
                "At least one role is required".to_string(),
            ));
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials for a role
    pub async fn generate_credentials(&self, role_name: &str) -> Result<AtlasUser> {
        let config = self.config.read().await;
        let config = config.as_ref().ok_or_else(|| {
            MongoDBAtlasError::ConfigError("MongoDB Atlas not configured".to_string())
        })?;

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| MongoDBAtlasError::RoleNotFound(role_name.to_string()))?;

        // Generate username
        let username = format!("secreton-{}", self.generate_random_string(8));

        // Generate password
        let password = self.generate_password(32);

        // Create user in Atlas (mock)
        self.create_atlas_user(config, &username, &password, role)
            .await?;

        let user = AtlasUser {
            username: username.clone(),
            password,
            database_name: role.database_name.clone(),
            roles: role.roles.clone(),
            scopes: role.scopes.clone(),
            project_id: role.project_id.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + role.ttl,
        };

        // Store user
        let mut users = self.users.write().await;
        users.insert(username, user.clone());

        Ok(user)
    }

    /// Generate random string
    fn generate_random_string(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate password
    fn generate_password(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Create user in Atlas
    async fn create_atlas_user(
        &self,
        _config: &MongoDBAtlasConfig,
        _username: &str,
        _password: &str,
        _role: &AtlasRole,
    ) -> Result<()> {
        // Mock implementation
        // Real implementation would call Atlas API:
        // POST /api/atlas/v1.0/groups/{project_id}/databaseUsers
        // Body: {
        //   "username": "...",
        //   "password": "...",
        //   "databaseName": "admin",
        //   "roles": [...],
        //   "scopes": [...]
        // }
        Ok(())
    }

    /// Assign additional roles to user
    pub async fn assign_roles(
        &self,
        username: &str,
        additional_roles: Vec<DatabaseRole>,
    ) -> Result<()> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(MongoDBAtlasError::ConfigError(
                "MongoDB Atlas not configured".to_string(),
            ));
        }

        let mut users = self.users.write().await;
        let user = users
            .get_mut(username)
            .ok_or_else(|| MongoDBAtlasError::UserNotFound(username.to_string()))?;

        // Add roles to user (mock)
        for role in additional_roles {
            if !user
                .roles
                .iter()
                .any(|r| r.role_name == role.role_name && r.database_name == role.database_name)
            {
                user.roles.push(role);
            }
        }

        Ok(())
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, username: &str) -> Result<()> {
        let config = self.config.read().await;
        let config = config.as_ref().ok_or_else(|| {
            MongoDBAtlasError::ConfigError("MongoDB Atlas not configured".to_string())
        })?;

        // Get user to get project_id
        let users = self.users.read().await;
        let user = users
            .get(username)
            .ok_or_else(|| MongoDBAtlasError::UserNotFound(username.to_string()))?;

        // Delete user from Atlas (mock)
        self.delete_atlas_user(config, &user.project_id, username)
            .await?;

        drop(users);

        // Remove from local storage
        let mut users = self.users.write().await;
        users.remove(username);

        Ok(())
    }

    /// Delete user from Atlas
    async fn delete_atlas_user(
        &self,
        _config: &MongoDBAtlasConfig,
        _project_id: &str,
        _username: &str,
    ) -> Result<()> {
        // Mock implementation
        // Real implementation would call:
        // DELETE /api/atlas/v1.0/groups/{project_id}/databaseUsers/admin/{username}
        Ok(())
    }

    /// Get role
    pub async fn get_role(&self, name: &str) -> Result<AtlasRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| MongoDBAtlasError::RoleNotFound(name.to_string()))
    }

    /// List all roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }

    /// Delete a role
    pub async fn delete_role(&self, name: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles
            .remove(name)
            .ok_or_else(|| MongoDBAtlasError::RoleNotFound(name.to_string()))?;
        Ok(())
    }

    /// List users
    pub async fn list_users(&self) -> Vec<String> {
        let users = self.users.read().await;
        users.keys().cloned().collect()
    }

    /// Get user
    pub async fn get_user(&self, username: &str) -> Result<AtlasUser> {
        let users = self.users.read().await;
        users
            .get(username)
            .cloned()
            .ok_or_else(|| MongoDBAtlasError::UserNotFound(username.to_string()))
    }

    /// Cleanup expired users
    pub async fn cleanup_expired_users(&self) -> Result<usize> {
        let config = self.config.read().await;
        let config = config.as_ref().ok_or_else(|| {
            MongoDBAtlasError::ConfigError("MongoDB Atlas not configured".to_string())
        })?;

        let mut users = self.users.write().await;
        let now = Utc::now();

        let expired: Vec<(String, String)> = users
            .iter()
            .filter(|(_, user)| user.expires_at < now)
            .map(|(username, user)| (username.clone(), user.project_id.clone()))
            .collect();

        let count = expired.len();
        for (username, project_id) in expired {
            self.delete_atlas_user(config, &project_id, &username)
                .await?;
            users.remove(&username);
        }

        Ok(count)
    }
}

impl Default for MongoDBAtlasEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> MongoDBAtlasConfig {
        MongoDBAtlasConfig {
            public_key: "test_public_key".to_string(),
            private_key: "test_private_key".to_string(),
            project_id: "5f8a1b2c3d4e5f6a7b8c9d0e".to_string(),
        }
    }

    #[tokio::test]
    async fn test_configure_mongodb_atlas() {
        let engine = MongoDBAtlasEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        let cfg = engine.config.read().await;
        assert!(cfg.is_some());
        assert_eq!(cfg.as_ref().unwrap().public_key, "test_public_key");
    }

    #[tokio::test]
    async fn test_generate_user_with_readwrite_role() {
        let engine = MongoDBAtlasEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = AtlasRole {
            name: "app-role".to_string(),
            project_id: "5f8a1b2c3d4e5f6a7b8c9d0e".to_string(),
            database_name: "myapp".to_string(),
            roles: vec![DatabaseRole {
                role_name: "readWrite".to_string(),
                database_name: "myapp".to_string(),
                collection_name: None,
            }],
            scopes: vec!["cluster-1".to_string()],
            ttl: Duration::hours(24),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("app-role").await.unwrap();

        assert!(user.username.starts_with("secreton-"));
        assert_eq!(user.password.len(), 32);
        assert_eq!(user.database_name, "myapp");
        assert_eq!(user.roles.len(), 1);
        assert_eq!(user.roles[0].role_name, "readWrite");
        assert_eq!(user.scopes.len(), 1);
        assert_eq!(user.scopes[0], "cluster-1");
    }

    #[tokio::test]
    async fn test_assign_additional_roles() {
        let engine = MongoDBAtlasEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = AtlasRole {
            name: "basic-role".to_string(),
            project_id: "5f8a1b2c3d4e5f6a7b8c9d0e".to_string(),
            database_name: "testdb".to_string(),
            roles: vec![DatabaseRole {
                role_name: "read".to_string(),
                database_name: "testdb".to_string(),
                collection_name: None,
            }],
            scopes: vec!["cluster-1".to_string()],
            ttl: Duration::hours(12),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("basic-role").await.unwrap();
        let username = user.username.clone();

        // Initially has 1 role
        assert_eq!(user.roles.len(), 1);

        // Assign additional roles
        let additional = vec![
            DatabaseRole {
                role_name: "readWrite".to_string(),
                database_name: "testdb".to_string(),
                collection_name: None,
            },
            DatabaseRole {
                role_name: "dbAdmin".to_string(),
                database_name: "testdb".to_string(),
                collection_name: None,
            },
        ];

        engine.assign_roles(&username, additional).await.unwrap();

        // Should now have 3 roles
        let updated_user = engine.get_user(&username).await.unwrap();
        assert_eq!(updated_user.roles.len(), 3);
    }

    #[tokio::test]
    async fn test_revoke_credentials() {
        let engine = MongoDBAtlasEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = AtlasRole {
            name: "temp-role".to_string(),
            project_id: "5f8a1b2c3d4e5f6a7b8c9d0e".to_string(),
            database_name: "tempdb".to_string(),
            roles: vec![DatabaseRole {
                role_name: "readWrite".to_string(),
                database_name: "tempdb".to_string(),
                collection_name: None,
            }],
            scopes: vec![],
            ttl: Duration::hours(1),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("temp-role").await.unwrap();
        let username = user.username.clone();

        // User should exist
        assert!(engine.get_user(&username).await.is_ok());

        // Revoke credentials
        engine.revoke_credentials(&username).await.unwrap();

        // User should not exist
        assert!(engine.get_user(&username).await.is_err());
    }

    #[tokio::test]
    async fn test_role_crud_operations() {
        let engine = MongoDBAtlasEngine::new();

        let role = AtlasRole {
            name: "test-role".to_string(),
            project_id: "5f8a1b2c3d4e5f6a7b8c9d0e".to_string(),
            database_name: "testdb".to_string(),
            roles: vec![DatabaseRole {
                role_name: "read".to_string(),
                database_name: "testdb".to_string(),
                collection_name: Some("users".to_string()),
            }],
            scopes: vec!["cluster-1".to_string(), "cluster-2".to_string()],
            ttl: Duration::hours(6),
        };

        // Create
        engine.create_role(role.clone()).await.unwrap();

        // Read
        let retrieved = engine.get_role("test-role").await.unwrap();
        assert_eq!(retrieved.name, "test-role");
        assert_eq!(retrieved.scopes.len(), 2);

        // List
        let roles = engine.list_roles().await;
        assert_eq!(roles.len(), 1);
        assert!(roles.contains(&"test-role".to_string()));

        // Delete
        engine.delete_role("test-role").await.unwrap();
        assert!(engine.get_role("test-role").await.is_err());
    }

    #[tokio::test]
    async fn test_collection_scoped_role() {
        let engine = MongoDBAtlasEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = AtlasRole {
            name: "collection-role".to_string(),
            project_id: "5f8a1b2c3d4e5f6a7b8c9d0e".to_string(),
            database_name: "analytics".to_string(),
            roles: vec![DatabaseRole {
                role_name: "read".to_string(),
                database_name: "analytics".to_string(),
                collection_name: Some("events".to_string()),
            }],
            scopes: vec!["analytics-cluster".to_string()],
            ttl: Duration::hours(24),
        };

        engine.create_role(role).await.unwrap();

        let user = engine
            .generate_credentials("collection-role")
            .await
            .unwrap();

        assert_eq!(user.roles.len(), 1);
        assert_eq!(user.roles[0].collection_name, Some("events".to_string()));
    }
}
