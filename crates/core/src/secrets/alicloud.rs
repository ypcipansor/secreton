// AliCloud Secrets Engine - Alibaba Cloud RAM dynamic credential generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum AliCloudError {
    #[error("AliCloud error: {0}")]
    AliCloudError(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("API error: {0}")]
    APIError(String),
}

pub type Result<T> = std::result::Result<T, AliCloudError>;

/// RAM role type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RoleType {
    RamUser, // Create RAM user with access keys
    RamRole, // Assume RAM role
    STS,     // Generate STS token
}

/// Policy type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyType {
    System, // System-managed policy
    Custom, // Custom inline policy
}

/// AliCloud configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliCloudConfig {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub region: String,   // e.g., cn-hangzhou
    pub endpoint: String, // e.g., ram.aliyuncs.com
}

/// Policy document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub policy_name: String,
    pub policy_type: PolicyType,
    pub document: String, // JSON policy document
}

/// AliCloud role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliCloudRole {
    pub name: String,
    pub role_type: RoleType,
    pub policies: Vec<PolicyDocument>,
    pub inline_policies: Vec<String>, // Inline policy JSON
    pub role_arn: Option<String>,     // For RamRole type
    pub ttl: Duration,
}

/// Generated AliCloud credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliCloudCredential {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub security_token: Option<String>, // For STS tokens
    pub expiration: DateTime<Utc>,
    pub user_name: Option<String>, // For RamUser
    pub role_arn: Option<String>,  // For RamRole/STS
}

/// AliCloud secrets engine
pub struct AliCloudEngine {
    config: Arc<RwLock<Option<AliCloudConfig>>>,
    roles: Arc<RwLock<HashMap<String, AliCloudRole>>>,
    users: Arc<RwLock<HashMap<String, AliCloudCredential>>>,
}

impl AliCloudEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure AliCloud connection
    pub async fn configure(&self, config: AliCloudConfig) -> Result<()> {
        if config.access_key_id.is_empty() {
            return Err(AliCloudError::ConfigError(
                "Access key ID is required".to_string(),
            ));
        }
        if config.access_key_secret.is_empty() {
            return Err(AliCloudError::ConfigError(
                "Access key secret is required".to_string(),
            ));
        }
        if config.region.is_empty() {
            return Err(AliCloudError::ConfigError("Region is required".to_string()));
        }

        // Validate credentials (mock)
        self.validate_credentials(&config).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Validate AliCloud credentials
    async fn validate_credentials(&self, _config: &AliCloudConfig) -> Result<()> {
        // Mock validation
        // Real implementation would:
        // 1. Call RAM API to verify credentials
        // 2. Check permissions
        // 3. Verify region endpoint
        Ok(())
    }

    /// Create a role
    pub async fn create_role(&self, role: AliCloudRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(AliCloudError::ConfigError(
                "Role name is required".to_string(),
            ));
        }

        // Validate role based on type
        match role.role_type {
            RoleType::RamRole | RoleType::STS => {
                if role.role_arn.is_none() {
                    return Err(AliCloudError::ConfigError(
                        "Role ARN is required for RamRole/STS".to_string(),
                    ));
                }
            }
            RoleType::RamUser => {
                // No additional validation needed
            }
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials for a role
    pub async fn generate_credentials(&self, role_name: &str) -> Result<AliCloudCredential> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| AliCloudError::ConfigError("AliCloud not configured".to_string()))?;

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| AliCloudError::RoleNotFound(role_name.to_string()))?;

        let credential = match role.role_type {
            RoleType::RamUser => {
                // Create RAM user
                let user_name = format!("secreton-{}", uuid::Uuid::new_v4());
                let access_key_id = format!("LTAI{}", self.generate_random_string(16));
                let access_key_secret = self.generate_random_string(30);

                // Create user via RAM API (mock)
                self.create_ram_user(config, &user_name).await?;

                // Attach policies
                for policy in &role.policies {
                    self.attach_policy(config, &user_name, policy).await?;
                }

                AliCloudCredential {
                    access_key_id,
                    access_key_secret,
                    security_token: None,
                    expiration: Utc::now() + role.ttl,
                    user_name: Some(user_name),
                    role_arn: None,
                }
            }
            RoleType::RamRole => {
                // Assume RAM role
                let access_key_id = format!("STS.{}", self.generate_random_string(16));
                let access_key_secret = self.generate_random_string(30);
                let security_token = self.generate_random_string(40);

                AliCloudCredential {
                    access_key_id,
                    access_key_secret,
                    security_token: Some(security_token),
                    expiration: Utc::now() + role.ttl,
                    user_name: None,
                    role_arn: role.role_arn.clone(),
                }
            }
            RoleType::STS => {
                // Generate STS token
                let access_key_id = format!("STS.{}", self.generate_random_string(16));
                let access_key_secret = self.generate_random_string(30);
                let security_token = self.generate_random_string(40);

                AliCloudCredential {
                    access_key_id,
                    access_key_secret,
                    security_token: Some(security_token),
                    expiration: Utc::now() + role.ttl,
                    user_name: None,
                    role_arn: role.role_arn.clone(),
                }
            }
        };

        // Store credential
        let mut users = self.users.write().await;
        users.insert(credential.access_key_id.clone(), credential.clone());

        Ok(credential)
    }

    /// Generate random string
    fn generate_random_string(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Create RAM user
    async fn create_ram_user(&self, _config: &AliCloudConfig, _user_name: &str) -> Result<()> {
        // Mock implementation
        // Real implementation would call RAM API:
        // POST https://ram.aliyuncs.com/?Action=CreateUser
        Ok(())
    }

    /// Attach policy to user
    async fn attach_policy(
        &self,
        _config: &AliCloudConfig,
        _user_name: &str,
        _policy: &PolicyDocument,
    ) -> Result<()> {
        // Mock implementation
        // Real implementation would call:
        // POST https://ram.aliyuncs.com/?Action=AttachPolicyToUser
        Ok(())
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, access_key_id: &str) -> Result<()> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| AliCloudError::ConfigError("AliCloud not configured".to_string()))?;

        let users = self.users.read().await;
        let credential = users
            .get(access_key_id)
            .ok_or_else(|| AliCloudError::UserNotFound(access_key_id.to_string()))?;

        // Delete RAM user if it's a RamUser
        if let Some(user_name) = &credential.user_name {
            self.delete_ram_user(config, user_name).await?;
        }

        drop(users);

        // Remove from local storage
        let mut users = self.users.write().await;
        users.remove(access_key_id);

        Ok(())
    }

    /// Delete RAM user
    async fn delete_ram_user(&self, _config: &AliCloudConfig, _user_name: &str) -> Result<()> {
        // Mock implementation
        // Real implementation would call:
        // POST https://ram.aliyuncs.com/?Action=DeleteUser
        Ok(())
    }

    /// Rotate root credentials
    pub async fn rotate_root_credentials(&self) -> Result<AliCloudConfig> {
        let mut config = self.config.write().await;
        let current_config = config
            .as_ref()
            .ok_or_else(|| AliCloudError::ConfigError("AliCloud not configured".to_string()))?;

        // Generate new access keys (mock)
        let new_access_key_id = format!("LTAI{}", self.generate_random_string(16));
        let new_access_key_secret = self.generate_random_string(30);

        let new_config = AliCloudConfig {
            access_key_id: new_access_key_id,
            access_key_secret: new_access_key_secret,
            region: current_config.region.clone(),
            endpoint: current_config.endpoint.clone(),
        };

        *config = Some(new_config.clone());

        Ok(new_config)
    }

    /// Get role
    pub async fn get_role(&self, name: &str) -> Result<AliCloudRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| AliCloudError::RoleNotFound(name.to_string()))
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
            .ok_or_else(|| AliCloudError::RoleNotFound(name.to_string()))?;
        Ok(())
    }

    /// List users
    pub async fn list_users(&self) -> Vec<String> {
        let users = self.users.read().await;
        users.keys().cloned().collect()
    }

    /// Get credential
    pub async fn get_credential(&self, access_key_id: &str) -> Result<AliCloudCredential> {
        let users = self.users.read().await;
        users
            .get(access_key_id)
            .cloned()
            .ok_or_else(|| AliCloudError::UserNotFound(access_key_id.to_string()))
    }

    /// Cleanup expired credentials
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| AliCloudError::ConfigError("AliCloud not configured".to_string()))?;

        let mut users = self.users.write().await;
        let now = Utc::now();

        let expired: Vec<(String, Option<String>)> = users
            .iter()
            .filter(|(_, cred)| cred.expiration < now)
            .map(|(key, cred)| (key.clone(), cred.user_name.clone()))
            .collect();

        let count = expired.len();
        for (access_key_id, user_name) in expired {
            if let Some(name) = user_name {
                self.delete_ram_user(config, &name).await?;
            }
            users.remove(&access_key_id);
        }

        Ok(count)
    }
}

impl Default for AliCloudEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AliCloudConfig {
        AliCloudConfig {
            access_key_id: "LTAI4test1234567890ab".to_string(),
            access_key_secret: "test_secret_1234567890abcdef".to_string(),
            region: "cn-hangzhou".to_string(),
            endpoint: "ram.aliyuncs.com".to_string(),
        }
    }

    #[tokio::test]
    async fn test_configure_alicloud() {
        let engine = AliCloudEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        let cfg = engine.config.read().await;
        assert!(cfg.is_some());
        assert_eq!(cfg.as_ref().unwrap().region, "cn-hangzhou");
    }

    #[tokio::test]
    async fn test_generate_ram_user_with_policies() {
        let engine = AliCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = AliCloudRole {
            name: "app-role".to_string(),
            role_type: RoleType::RamUser,
            policies: vec![
                PolicyDocument {
                    policy_name: "AliyunOSSReadOnlyAccess".to_string(),
                    policy_type: PolicyType::System,
                    document: "{}".to_string(),
                },
                PolicyDocument {
                    policy_name: "AliyunECSReadOnlyAccess".to_string(),
                    policy_type: PolicyType::System,
                    document: "{}".to_string(),
                },
            ],
            inline_policies: vec![],
            role_arn: None,
            ttl: Duration::hours(24),
        };

        engine.create_role(role).await.unwrap();

        let cred = engine.generate_credentials("app-role").await.unwrap();

        assert!(cred.access_key_id.starts_with("LTAI"));
        assert_eq!(cred.access_key_secret.len(), 30);
        assert!(cred.security_token.is_none());
        assert!(cred.user_name.is_some());
        assert!(cred.user_name.as_ref().unwrap().starts_with("secreton-"));
    }

    #[tokio::test]
    async fn test_generate_sts_token() {
        let engine = AliCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = AliCloudRole {
            name: "sts-role".to_string(),
            role_type: RoleType::STS,
            policies: vec![],
            inline_policies: vec![],
            role_arn: Some("acs:ram::123456789:role/MyRole".to_string()),
            ttl: Duration::hours(1),
        };

        engine.create_role(role).await.unwrap();

        let cred = engine.generate_credentials("sts-role").await.unwrap();

        assert!(cred.access_key_id.starts_with("STS."));
        assert!(cred.security_token.is_some());
        assert_eq!(cred.security_token.as_ref().unwrap().len(), 40);
        assert!(cred.user_name.is_none());
        assert_eq!(
            cred.role_arn,
            Some("acs:ram::123456789:role/MyRole".to_string())
        );
    }

    #[tokio::test]
    async fn test_attach_custom_policies() {
        let engine = AliCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let custom_policy = r#"
        {
            "Version": "1",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["oss:GetObject"],
                "Resource": ["acs:oss:*:*:mybucket/*"]
            }]
        }
        "#;

        let role = AliCloudRole {
            name: "custom-role".to_string(),
            role_type: RoleType::RamUser,
            policies: vec![PolicyDocument {
                policy_name: "CustomOSSPolicy".to_string(),
                policy_type: PolicyType::Custom,
                document: custom_policy.to_string(),
            }],
            inline_policies: vec![custom_policy.to_string()],
            role_arn: None,
            ttl: Duration::hours(12),
        };

        engine.create_role(role).await.unwrap();

        let cred = engine.generate_credentials("custom-role").await.unwrap();

        assert!(cred.user_name.is_some());
    }

    #[tokio::test]
    async fn test_revoke_ram_user() {
        let engine = AliCloudEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = AliCloudRole {
            name: "temp-role".to_string(),
            role_type: RoleType::RamUser,
            policies: vec![],
            inline_policies: vec![],
            role_arn: None,
            ttl: Duration::hours(1),
        };

        engine.create_role(role).await.unwrap();

        let cred = engine.generate_credentials("temp-role").await.unwrap();
        let access_key_id = cred.access_key_id.clone();

        // Credential should exist
        assert!(engine.get_credential(&access_key_id).await.is_ok());

        // Revoke credential
        engine.revoke_credentials(&access_key_id).await.unwrap();

        // Credential should not exist
        assert!(engine.get_credential(&access_key_id).await.is_err());
    }

    #[tokio::test]
    async fn test_rotate_root_credentials() {
        let engine = AliCloudEngine::new();
        let original_config = create_test_config();
        let original_key_id = original_config.access_key_id.clone();

        engine.configure(original_config).await.unwrap();

        let new_config = engine.rotate_root_credentials().await.unwrap();

        assert_ne!(new_config.access_key_id, original_key_id);
        assert!(new_config.access_key_id.starts_with("LTAI"));
        assert_eq!(new_config.region, "cn-hangzhou");
    }
}
