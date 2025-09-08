//! AppRole Authentication Method
//! 
//! Provides machine-to-machine authentication using role IDs and secret IDs.
//! Critical for CI/CD pipelines, automation, and service-to-service authentication.
//! 
//! Features:
//! - Role ID and Secret ID generation
//! - Policy binding and enforcement  
//! - Token TTL management
//! - Secure credential distribution
//! - Audit trail for machine access

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json;
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use super::traits::{AuthMethod, Credentials, AuthResult as CoreAuthResult, TokenInfo};
use crate::storage::{StorageEngine, StorageEntry};
use crate::audit::AuditLogger;

pub mod config;
pub mod role;
pub mod secret;

pub use config::AppRoleConfig;
pub use role::AppRole;
pub use secret::SecretId;

#[derive(Clone)]
pub struct AppRoleAuth {
    storage: Arc<dyn StorageEngine>,
    audit_logger: AuditLogger,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppRoleCredentials {
    pub role_id: String,
    pub secret_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub token: Option<String>,
    pub policies: Vec<String>,
    pub ttl: u64,
    pub renewable: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub role_id: String,
    pub secret_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub token_policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub lease_duration: u64,
    pub renewable: bool,
    pub entity_id: String,
}

impl AppRoleAuth {
    /// Create a new AppRole authentication method
    pub fn new(
        storage: Arc<dyn StorageEngine>,
        audit_logger: AuditLogger,
    ) -> Self {
        Self {
            storage,
            audit_logger,
        }
    }

    /// Create a new AppRole with specified configuration
    pub async fn create_role(
        &self,
        role_name: &str,
        role: AppRole,
    ) -> Result<()> {
        // Generate unique role ID
        let role_id = Uuid::new_v4().to_string();
        
        // Create role entry with role ID
        let mut role_with_id = role.clone();
        role_with_id.role_id = role_id.clone();
        
        // Store role configuration
        let role_key = format!("auth/approle/role/{}", role_name);
        let storage_entry = StorageEntry {
            key: role_key.clone(),
            value: serde_json::to_vec(&role_with_id)?,
            metadata: HashMap::new(),
        };
        self.storage.put(storage_entry).await?;
        
        // Store role_id -> role_name mapping
        let role_id_key = format!("auth/approle/role-id/{}", role_id);
        let role_id_entry = StorageEntry {
            key: role_id_key.clone(),
            value: role_name.as_bytes().to_vec(),
            metadata: HashMap::new(),
        };
        self.storage.put(role_id_entry).await?;
        
        // Audit log
        // Log the role creation
        let audit_log = crate::audit::AuditLog {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            action: "approle.role.create".to_string(),
            actor: None,
            resource_type: "approle_role".to_string(),
            resource_id: role_name.to_string(),
            status: crate::audit::AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: [
                ("role_name".to_string(), role_name.to_string()),
                ("role_id".to_string(), role_id.clone()),
            ].into_iter().collect(),
        };
        self.audit_logger.log(audit_log).await?;
        
        Ok(())
    }

    /// Generate a new secret ID for a role
    pub async fn generate_secret_id(
        &self,
        role_name: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<SecretId> {
        // Verify role exists
        let role_key = format!("auth/approle/role/{}", role_name);
        let role_entry = self.storage.get(&role_key).await?
            .ok_or_else(|| anyhow!("Role not found"))?;
        let role: AppRole = serde_json::from_slice(&role_entry.value)?;
        
        // Generate secret ID
        let secret_id = Uuid::new_v4().to_string();
        let accessor = Uuid::new_v4().to_string();
        
        // Hash the secret ID for storage
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let secret_hash = argon2.hash_password(secret_id.as_bytes(), &salt)
            .map_err(|e| anyhow!("Failed to hash secret ID: {}", e))?
            .to_string();
        
        let secret_id_data = SecretId {
            secret_id_hash: secret_hash,
            accessor: accessor.clone(),
            role_name: role_name.to_string(),
            metadata: metadata.unwrap_or_default(),
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expiration_time: role.secret_id_ttl.map(|ttl| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + ttl
            }),
            num_uses: role.secret_id_num_uses,
            used_count: 0,
            cidr_list: None,
            active: true,
            token_bound_cidrs: None,
        };
        
        // Store secret ID data
        let secret_key = format!("auth/approle/secret-id/{}", accessor);
        let secret_entry = StorageEntry {
            key: secret_key.clone(),
            value: serde_json::to_vec(&secret_id_data)?,
            metadata: HashMap::new(),
        };
        self.storage.put(secret_entry).await?;
        
        // Store accessor -> secret_id mapping for lookup
        let accessor_key = format!("auth/approle/secret-id-accessor/{}", accessor);
        let accessor_entry = StorageEntry {
            key: accessor_key.clone(),
            value: secret_id.as_bytes().to_vec(),
            metadata: HashMap::new(),
        };
        self.storage.put(accessor_entry).await?;
        
        // Audit log
        let audit_log = crate::audit::AuditLog {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            action: "approle.secret_id.generate".to_string(),
            actor: None,
            resource_type: "approle_secret_id".to_string(),
            resource_id: accessor.clone(),
            status: crate::audit::AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: [
                ("role_name".to_string(), role_name.to_string()),
                ("accessor".to_string(), accessor.clone()),
            ].into_iter().collect(),
        };
        self.audit_logger.log(audit_log).await?;
        
        Ok(SecretId {
            secret_id_hash: secret_id, // Return plaintext secret ID for client use
            accessor,
            role_name: role_name.to_string(),
            metadata: secret_id_data.metadata,
            creation_time: secret_id_data.creation_time,
            expiration_time: secret_id_data.expiration_time,
            num_uses: secret_id_data.num_uses,
            used_count: 0,
            cidr_list: None,
            active: true,
            token_bound_cidrs: None,
        })
    }

    /// Authenticate using role ID and secret ID
    pub async fn login(
        &self,
        role_id: &str,
        secret_id: &str,
    ) -> Result<LoginResponse> {
        // Get role name from role ID
        let role_id_key = format!("auth/approle/role-id/{}", role_id);
        let role_name_entry = self.storage.get(&role_id_key).await?
            .ok_or_else(|| anyhow!("Invalid role ID"))?;
        let role_name = String::from_utf8(role_name_entry.value)?;
        
        // Get role configuration
        let role_key = format!("auth/approle/role/{}", role_name);
        let role_entry = self.storage.get(&role_key).await?
            .ok_or_else(|| anyhow!("Role not found"))?;
        let role: AppRole = serde_json::from_slice(&role_entry.value)?;
        
        // Find secret ID by trying all accessors (in production, use indexed lookup)
        let mut secret_data: Option<SecretId> = None;
        let mut secret_accessor = String::new();
        
        // In a real implementation, we'd have an index for efficient lookup
        // For now, we'll check against the secret ID hash
        for full_accessor_key in self.storage.list("auth/approle/secret-id-accessor/").await? {
            // Extract just the accessor UUID from the full key
            let accessor_result = full_accessor_key.strip_prefix("auth/approle/secret-id-accessor/")
                .unwrap_or(&full_accessor_key);
            
            if let Some(_accessor_entry) = self.storage.get(&full_accessor_key).await? {
                // Get the secret ID data
                let secret_key = format!("auth/approle/secret-id/{}", accessor_result);
                if let Some(secret_entry) = self.storage.get(&secret_key).await? {
                    if let Ok(secret_id_data) = serde_json::from_slice::<SecretId>(&secret_entry.value) {
                        // Verify the secret ID hash
                        if let Ok(parsed_hash) = PasswordHash::new(&secret_id_data.secret_id_hash) {
                            let argon2 = Argon2::default();
                            if argon2.verify_password(secret_id.as_bytes(), &parsed_hash).is_ok() {
                                // Check if secret ID belongs to this role
                                if secret_id_data.role_name == role_name {
                                    secret_accessor = accessor_result.to_string();
                                    secret_data = Some(secret_id_data);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        let mut secret_id_data = secret_data.ok_or_else(|| anyhow!("Invalid secret ID"))?;
        
        // Check expiration
        if let Some(expiration) = secret_id_data.expiration_time {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > expiration {
                return Err(anyhow!("Secret ID expired"));
            }
        }
        
        // Check usage count
        if let Some(max_uses) = secret_id_data.num_uses {
            if secret_id_data.used_count >= max_uses {
                return Err(anyhow!("Secret ID usage limit exceeded"));
            }
        }
        
        // Increment usage count
        secret_id_data.used_count += 1;
        let secret_key = format!("auth/approle/secret-id/{}", secret_accessor);
        let entry = StorageEntry {
            key: secret_key,
            value: serde_json::to_vec(&secret_id_data)?,
            metadata: HashMap::new(),
        };
        self.storage.put(entry).await?;
        
        // Generate authentication token
        let client_token = format!("hvs.{}", Uuid::new_v4().to_string().replace("-", ""));
        let accessor = Uuid::new_v4().to_string();
        let entity_id = format!("entity-{}", Uuid::new_v4());
        
        // Create token metadata
        let mut token_metadata = HashMap::new();
        token_metadata.insert("role_name".to_string(), role_name.clone());
        token_metadata.insert("auth_type".to_string(), "approle".to_string());
        
        // Add secret ID metadata
        for (key, value) in &secret_id_data.metadata {
            token_metadata.insert(format!("secret_id_{}", key), value.clone());
        }
        
        // Audit log successful authentication
        let audit_log = crate::audit::AuditLog {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            action: "approle.auth.success".to_string(),
            actor: Some(role_name.clone()),
            resource_type: "approle_auth".to_string(),
            resource_id: role_id.to_string(),
            status: crate::audit::AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: [
                ("role_name".to_string(), role_name.clone()),
                ("role_id".to_string(), role_id.to_string()),
                ("client_token".to_string(), client_token.clone()),
                ("accessor".to_string(), accessor.clone()),
            ].into_iter().collect(),
        };
        self.audit_logger.log(audit_log).await?;
        
        Ok(LoginResponse {
            client_token,
            accessor,
            policies: role.token_policies.clone(),
            token_policies: role.token_policies.clone(),
            metadata: token_metadata,
            lease_duration: role.token_ttl.unwrap_or(3600), // Default 1 hour
            renewable: true,
            entity_id,
        })
    }

    /// List all roles
    pub async fn list_roles(&self) -> Result<Vec<String>> {
        let roles = self.storage.list("auth/approle/role/").await?
            .into_iter()
            .map(|key| key.trim_end_matches('/').to_string())
            .collect();
        
        Ok(roles)
    }

    /// Get role information
    pub async fn get_role(&self, role_name: &str) -> Result<Option<AppRole>> {
        let role_key = format!("auth/approle/role/{}", role_name);
        if let Some(role_entry) = self.storage.get(&role_key).await? {
            let role: AppRole = serde_json::from_slice(&role_entry.value)?;
            Ok(Some(role))
        } else {
            Ok(None)
        }
    }

    /// Delete a role
    pub async fn delete_role(&self, role_name: &str) -> Result<()> {
        // Get role to find role ID
        let role_key = format!("auth/approle/role/{}", role_name);
        if let Some(role_entry) = self.storage.get(&role_key).await? {
            let role: AppRole = serde_json::from_slice(&role_entry.value)?;
            
            // Delete role ID mapping
            let role_id_key = format!("auth/approle/role-id/{}", role.role_id);
            self.storage.delete(&role_id_key).await?;
        }
        
        // Delete role
        self.storage.delete(&role_key).await?;
        
        // TODO: Clean up associated secret IDs
        
        // Audit log
        let audit_log = crate::audit::AuditLog {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            action: "approle.role.delete".to_string(),
            actor: None,
            resource_type: "approle_role".to_string(),
            resource_id: role_name.to_string(),
            status: crate::audit::AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: [
                ("role_name".to_string(), role_name.to_string()),
            ].into_iter().collect(),
        };
        self.audit_logger.log(audit_log).await?;
        
        Ok(())
    }

    /// List secret ID accessors for a role
    pub async fn list_secret_id_accessors(
        &self,
        role_name: &str,
    ) -> Result<Vec<String>> {
        let mut accessors = Vec::new();
        
        // Get all secret IDs and filter by role
        let secret_list = self.storage.list("auth/approle/secret-id/").await?;
        for accessor in secret_list {
            let secret_key = format!("auth/approle/secret-id/{}", accessor);
            if let Some(secret_entry) = self.storage.get(&secret_key).await? {
                if let Ok(secret_id_data) = serde_json::from_slice::<SecretId>(&secret_entry.value) {
                    if secret_id_data.role_name == role_name {
                        accessors.push(accessor);
                    }
                }
            }
        }
        
        Ok(accessors)
    }

    /// Destroy a secret ID by accessor
    pub async fn destroy_secret_id(
        &self,
        accessor: &str,
    ) -> Result<()> {
        let secret_key = format!("auth/approle/secret-id/{}", accessor);
        let accessor_key = format!("auth/approle/secret-id-accessor/{}", accessor);
        
        // Get secret ID data for audit
        if let Some(secret_entry) = self.storage.get(&secret_key).await? {
            if let Ok(secret_id_data) = serde_json::from_slice::<SecretId>(&secret_entry.value) {
                // Audit log
                let audit_log = crate::audit::AuditLog {
                    id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    action: "approle.secret_id.destroy".to_string(),
                    actor: None,
                    resource_type: "approle_secret_id".to_string(),
                    resource_id: accessor.to_string(),
                    status: crate::audit::AuditStatus::Success,
                    ip: None,
                    user_agent: None,
                    metadata: [
                        ("role_name".to_string(), secret_id_data.role_name.clone()),
                        ("accessor".to_string(), accessor.to_string()),
                    ].into_iter().collect(),
                };
                self.audit_logger.log(audit_log).await?;
            }
        }
        
        // Delete secret ID and accessor mapping
        self.storage.delete(&secret_key).await?;
        self.storage.delete(&accessor_key).await?;
        
        Ok(())
    }
}

#[async_trait]
impl AuthMethod for AppRoleAuth {
    async fn authenticate(&self, credentials: &Credentials) -> Result<CoreAuthResult> {
        // Extract role_id and secret_id from credentials
        let (role_id, secret_id) = match credentials {
            Credentials::AppRole { role_id, secret_id } => (role_id, secret_id),
            _ => return Err(anyhow!("Invalid credential type for AppRole authentication")),
        };
            
        match self.login(role_id, secret_id).await {
            Ok(response) => {
                Ok(CoreAuthResult {
                    success: true,
                    token: Some(TokenInfo {
                        id: response.client_token,
                        policies: response.policies.clone(),
                        metadata: response.metadata.clone(),
                        ttl: Some(response.lease_duration),
                        renewable: response.renewable,
                        entity_id: Some(response.entity_id),
                    }),
                    user_info: None,
                    policies: response.policies,
                    metadata: response.metadata,
                    error: None,
                })
            }
            Err(e) => {
                // Audit log failed authentication
                let audit_log = crate::audit::AuditLog {
                    id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    action: "approle.auth.failure".to_string(),
                    actor: None,
                    resource_type: "approle_auth".to_string(),
                    resource_id: role_id.to_string(),
                    status: crate::audit::AuditStatus::Failure,
                    ip: None,
                    user_agent: None,
                    metadata: [
                        ("error".to_string(), e.to_string()),
                    ].into_iter().collect(),
                };
                self.audit_logger.log(audit_log).await.ok(); // Don't fail on audit errors
                
                Ok(CoreAuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some(e.to_string()),
                })
            }
        }
    }

    async fn validate_config(&self, _config: &serde_json::Value) -> Result<()> {
        // AppRole config validation
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<String>> {
        // AppRole doesn't have traditional users, return roles instead
        self.list_roles().await
    }

    async fn create_user(&self, username: &str, _config: &serde_json::Value) -> Result<()> {
        // For AppRole, creating a "user" means creating a role
        let role_config = AppRole::default(); // Basic role configuration
        self.create_role(username, role_config).await
    }

    async fn delete_user(&self, username: &str) -> Result<()> {
        // For AppRole, deleting a "user" means deleting a role
        self.delete_role(username).await
    }

    fn name(&self) -> &'static str {
        "approle"
    }

    fn description(&self) -> &'static str {
        "AppRole authentication for machine-to-machine authentication using role IDs and secret IDs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::RwLock;
    use crate::error::CoreError;

    // Simple in-memory storage for testing
    #[derive(Debug, Default)]
    struct MockStorage {
        data: RwLock<HashMap<String, StorageEntry>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl StorageEngine for MockStorage {
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError> {
            let data = self.data.read().await;
            Ok(data.get(key).cloned())
        }

        async fn put(&self, entry: StorageEntry) -> Result<(), CoreError> {
            let mut data = self.data.write().await;
            data.insert(entry.key.clone(), entry);
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), CoreError> {
            let mut data = self.data.write().await;
            data.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError> {
            let data = self.data.read().await;
            let keys: Vec<String> = data
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect();
            Ok(keys)
        }
    }

    fn create_mock_audit_logger() -> AuditLogger {
        // Create a basic audit logger for testing
        let memory_backend = Arc::new(crate::audit::MemoryBackend::default());
        AuditLogger::new(vec![memory_backend])
    }

    #[tokio::test]
    async fn test_approle_authentication() {
        let storage = Arc::new(MockStorage::new());
        let audit_logger = create_mock_audit_logger();
        let approle_auth = AppRoleAuth::new(storage, audit_logger);

        // Create a test role with all required fields
        let role_config = AppRole::default()
            .with_token_policies(vec!["default".to_string(), "app-policy".to_string()])
            .with_token_ttl(3600)
            .with_token_max_ttl(7200)
            .with_secret_id_ttl(86400)
            .with_secret_id_num_uses(10)
            .with_bind_secret_id(true);

        approle_auth.create_role("test-app", role_config).await.unwrap();

        // Generate secret ID
        let mut metadata = HashMap::new();
        metadata.insert("app_name".to_string(), "test-application".to_string());
        let secret_id = approle_auth.generate_secret_id("test-app", Some(metadata)).await.unwrap();

        // Get role to find role ID
        let role = approle_auth.get_role("test-app").await.unwrap().unwrap();

        // Test authentication
        let login_response = approle_auth.login(&role.role_id, &secret_id.secret_id_hash).await.unwrap();
        
        assert_eq!(login_response.policies, vec!["default", "app-policy"]);
        assert_eq!(login_response.lease_duration, 3600);
        assert!(login_response.renewable);
        assert_eq!(login_response.metadata.get("role_name").unwrap(), "test-app");
    }

    #[tokio::test]
    async fn test_secret_id_expiration() {
        let storage = Arc::new(MockStorage::new());
        let audit_logger = create_mock_audit_logger();
        let approle_auth = AppRoleAuth::new(storage, audit_logger);

        // Create role with very short secret ID TTL
        let role_config = AppRole::default()
            .with_token_policies(vec!["default".to_string()])
            .with_token_ttl(3600)
            .with_token_max_ttl(7200)
            .with_secret_id_ttl(1) // 1 second
            .with_bind_secret_id(true);

        approle_auth.create_role("test-app", role_config).await.unwrap();
        let secret_id = approle_auth.generate_secret_id("test-app", None).await.unwrap();
        let role = approle_auth.get_role("test-app").await.unwrap().unwrap();

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Authentication should fail
        let result = approle_auth.login(&role.role_id, &secret_id.secret_id_hash).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_secret_id_usage_limit() {
        let storage = Arc::new(MockStorage::new());
        let audit_logger = create_mock_audit_logger();
        let approle_auth = AppRoleAuth::new(storage, audit_logger);

        // Create role with usage limit
        let role_config = AppRole::default()
            .with_token_policies(vec!["default".to_string()])
            .with_token_ttl(3600)
            .with_token_max_ttl(7200)
            .with_secret_id_num_uses(2) // Only 2 uses
            .with_bind_secret_id(true);

        approle_auth.create_role("test-app", role_config).await.unwrap();
        let secret_id = approle_auth.generate_secret_id("test-app", None).await.unwrap();
        let role = approle_auth.get_role("test-app").await.unwrap().unwrap();

        // First two uses should succeed
        approle_auth.login(&role.role_id, &secret_id.secret_id_hash).await.unwrap();
        approle_auth.login(&role.role_id, &secret_id.secret_id_hash).await.unwrap();

        // Third use should fail
        let result = approle_auth.login(&role.role_id, &secret_id.secret_id_hash).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("usage limit"));
    }
}
