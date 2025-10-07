// Oracle Cloud Infrastructure (OCI) Secrets Engine - Dynamic credential generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum OCIError {
    #[error("OCI error: {0}")]
    OCIError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Credential generation failed: {0}")]
    CredentialError(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
}

pub type Result<T> = std::result::Result<T, OCIError>;

/// OCI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCIConfig {
    pub user_ocid: String,           // ocid1.user.oc1..aaaaaa...
    pub tenancy_ocid: String,        // ocid1.tenancy.oc1..aaaaaa...
    pub region: String,              // e.g., us-phoenix-1
    pub fingerprint: String,         // RSA key fingerprint (MD5)
    pub private_key_path: String,    // Path to PEM private key
    pub compartment_id: String,      // ocid1.compartment.oc1..aaaaaa...
}

/// OCI role type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RoleType {
    User,          // IAM user
    Group,         // IAM group
    DynamicGroup,  // Dynamic group (for compute instances)
}

/// Policy statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatement {
    pub verb: String,           // Allow or Deny
    pub subject: String,        // group, user, dynamic-group
    pub resource: String,       // resource type
    pub permission: String,     // manage, use, read, inspect
    pub location: String,       // compartment, tenancy
    pub condition: Option<String>,
}

/// OCI role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCIRole {
    pub name: String,
    pub role_type: RoleType,
    pub policies: Vec<PolicyStatement>,
    pub compartment_id: String,
    pub ttl: u64, // seconds
    pub max_ttl: Option<u64>,
}

/// OCI credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCICredential {
    pub user_ocid: String,         // ocid1.user.oc1..{60-char}
    pub api_key_fingerprint: String, // MD5 fingerprint
    pub private_key: String,       // PEM format
    pub tenancy_ocid: String,
    pub compartment_id: String,
    pub region: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// OCI IAM user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCIUser {
    pub user_ocid: String,
    pub name: String,
    pub description: String,
    pub compartment_id: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Oracle Cloud Infrastructure Secrets Engine
pub struct OCISecretsEngine {
    config: Arc<RwLock<Option<OCIConfig>>>,
    roles: Arc<RwLock<HashMap<String, OCIRole>>>,
    credentials: Arc<RwLock<HashMap<String, OCICredential>>>,
    users: Arc<RwLock<HashMap<String, OCIUser>>>,
}

impl OCISecretsEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure OCI credentials
    pub async fn configure(&self, config: OCIConfig) -> Result<()> {
        // Validate OCID format
        if !config.user_ocid.starts_with("ocid1.user.oc1..") {
            return Err(OCIError::ConfigError(
                "Invalid user OCID format".to_string(),
            ));
        }

        if !config.tenancy_ocid.starts_with("ocid1.tenancy.oc1..") {
            return Err(OCIError::ConfigError(
                "Invalid tenancy OCID format".to_string(),
            ));
        }

        // Validate region
        if config.region.is_empty() {
            return Err(OCIError::ConfigError("Region is required".to_string()));
        }

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Create role
    pub async fn create_role(&self, role: OCIRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(OCIError::ConfigError("Role name is required".to_string()));
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials
    pub async fn generate_credentials(&self, role_name: &str) -> Result<OCICredential> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| OCIError::ConfigError("OCI not configured".to_string()))?;

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| OCIError::RoleNotFound(role_name.to_string()))?;

        // Generate credentials based on role type
        let credential = match role.role_type {
            RoleType::User => self.create_oci_user(config, role).await?,
            RoleType::Group => {
                return Err(OCIError::CredentialError(
                    "Group credentials not yet implemented".to_string(),
                ))
            }
            RoleType::DynamicGroup => {
                return Err(OCIError::CredentialError(
                    "Dynamic group credentials not yet implemented".to_string(),
                ))
            }
        };

        let mut credentials = self.credentials.write().await;
        credentials.insert(credential.user_ocid.clone(), credential.clone());

        Ok(credential)
    }

    /// Create OCI IAM user
    async fn create_oci_user(&self, config: &OCIConfig, role: &OCIRole) -> Result<OCICredential> {
        // Generate user OCID (mock)
        let user_ocid = format!(
            "ocid1.user.oc1..{}",
            self.generate_random_string(60)
        );

        let user_name = format!("vault-{}", self.generate_random_string(8));

        // Create user via OCI IAM API (mock)
        let user = OCIUser {
            user_ocid: user_ocid.clone(),
            name: user_name,
            description: format!("Vault-generated user for role {}", role.name),
            compartment_id: config.compartment_id.clone(),
            email: None,
            created_at: Utc::now(),
            is_active: true,
        };

        let mut users = self.users.write().await;
        users.insert(user_ocid.clone(), user);
        drop(users);

        // Generate API key pair
        let (private_key, fingerprint) = self.generate_api_key_pair().await?;

        // Attach policies
        self.attach_policies(&user_ocid, &role.policies).await?;

        let credential = OCICredential {
            user_ocid: user_ocid.clone(),
            api_key_fingerprint: fingerprint,
            private_key,
            tenancy_ocid: config.tenancy_ocid.clone(),
            compartment_id: role.compartment_id.clone(),
            region: config.region.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(role.ttl as i64),
        };

        Ok(credential)
    }

    /// Generate API key pair
    async fn generate_api_key_pair(&self) -> Result<(String, String)> {
        // Mock RSA key generation
        // Real implementation would use openssl or rsa crate
        let private_key = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
            self.generate_random_string(64)
        );

        // Mock MD5 fingerprint (format: xx:xx:xx:xx:...)
        let fingerprint = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.random_hex(2), self.random_hex(2), self.random_hex(2), self.random_hex(2),
            self.random_hex(2), self.random_hex(2), self.random_hex(2), self.random_hex(2),
            self.random_hex(2), self.random_hex(2), self.random_hex(2), self.random_hex(2),
            self.random_hex(2), self.random_hex(2), self.random_hex(2), self.random_hex(2),
        );

        Ok((private_key, fingerprint))
    }

    /// Attach policies to user
    async fn attach_policies(
        &self,
        _user_ocid: &str,
        _policies: &[PolicyStatement],
    ) -> Result<()> {
        // Mock policy attachment
        // Real implementation would call OCI IAM API
        Ok(())
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, user_ocid: &str) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        credentials.remove(user_ocid);

        // Delete OCI user
        self.delete_oci_user(user_ocid).await?;

        Ok(())
    }

    /// Delete OCI user
    async fn delete_oci_user(&self, user_ocid: &str) -> Result<()> {
        let mut users = self.users.write().await;
        users.remove(user_ocid);

        // Mock OCI API call to delete user
        Ok(())
    }

    /// Rotate API key
    pub async fn rotate_api_key(&self, user_ocid: &str) -> Result<OCICredential> {
        let mut credentials = self.credentials.write().await;
        let credential = credentials
            .get_mut(user_ocid)
            .ok_or_else(|| OCIError::CredentialError("Credential not found".to_string()))?;

        // Generate new API key pair
        let (private_key, fingerprint) = self.generate_api_key_pair().await?;

        credential.private_key = private_key;
        credential.api_key_fingerprint = fingerprint;

        Ok(credential.clone())
    }

    /// Get role
    pub async fn get_role(&self, role_name: &str) -> Result<OCIRole> {
        let roles = self.roles.read().await;
        roles
            .get(role_name)
            .cloned()
            .ok_or_else(|| OCIError::RoleNotFound(role_name.to_string()))
    }

    /// List roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }

    /// Delete role
    pub async fn delete_role(&self, role_name: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles
            .remove(role_name)
            .ok_or_else(|| OCIError::RoleNotFound(role_name.to_string()))?;
        Ok(())
    }

    // Helper functions
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

    fn random_hex(&self, bytes: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..bytes)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect::<Vec<_>>()
            .join("")
    }
}

impl Default for OCISecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> OCIConfig {
        OCIConfig {
            user_ocid: "ocid1.user.oc1..aaaaaaaa".to_string(),
            tenancy_ocid: "ocid1.tenancy.oc1..bbbbbbbb".to_string(),
            region: "us-phoenix-1".to_string(),
            fingerprint: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99".to_string(),
            private_key_path: "/path/to/key.pem".to_string(),
            compartment_id: "ocid1.compartment.oc1..cccccccc".to_string(),
        }
    }

    fn create_test_role() -> OCIRole {
        let policy = PolicyStatement {
            verb: "Allow".to_string(),
            subject: "group Developers".to_string(),
            resource: "object-family".to_string(),
            permission: "manage".to_string(),
            location: "compartment Engineering".to_string(),
            condition: None,
        };

        OCIRole {
            name: "developer-role".to_string(),
            role_type: RoleType::User,
            policies: vec![policy],
            compartment_id: "ocid1.compartment.oc1..cccccccc".to_string(),
            ttl: 3600,
            max_ttl: Some(7200),
        }
    }

    #[tokio::test]
    async fn test_configure_oci() {
        let engine = OCISecretsEngine::new();
        let config = create_test_config();

        engine.configure(config.clone()).await.unwrap();

        let stored_config = engine.config.read().await;
        assert!(stored_config.is_some());
        assert_eq!(stored_config.as_ref().unwrap().region, "us-phoenix-1");
    }

    #[tokio::test]
    async fn test_create_role() {
        let engine = OCISecretsEngine::new();
        let role = create_test_role();

        engine.create_role(role.clone()).await.unwrap();

        let retrieved = engine.get_role("developer-role").await.unwrap();
        assert_eq!(retrieved.name, "developer-role");
        assert_eq!(retrieved.role_type, RoleType::User);
        assert_eq!(retrieved.policies.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_credentials() {
        let engine = OCISecretsEngine::new();
        let config = create_test_config();
        let role = create_test_role();

        engine.configure(config).await.unwrap();
        engine.create_role(role).await.unwrap();

        let credential = engine.generate_credentials("developer-role").await.unwrap();

        assert!(credential.user_ocid.starts_with("ocid1.user.oc1.."));
        assert!(credential.user_ocid.len() > 30);
        assert!(!credential.private_key.is_empty());
        assert!(credential.api_key_fingerprint.contains(':'));
        assert_eq!(credential.region, "us-phoenix-1");
    }

    #[tokio::test]
    async fn test_api_key_fingerprint_format() {
        let engine = OCISecretsEngine::new();
        let config = create_test_config();
        let role = create_test_role();

        engine.configure(config).await.unwrap();
        engine.create_role(role).await.unwrap();

        let credential = engine.generate_credentials("developer-role").await.unwrap();

        // Verify fingerprint format (MD5 colon-separated)
        let parts: Vec<&str> = credential.api_key_fingerprint.split(':').collect();
        assert_eq!(parts.len(), 16);
        for part in parts {
            assert_eq!(part.len(), 2);
        }
    }

    #[tokio::test]
    async fn test_revoke_credentials() {
        let engine = OCISecretsEngine::new();
        let config = create_test_config();
        let role = create_test_role();

        engine.configure(config).await.unwrap();
        engine.create_role(role).await.unwrap();

        let credential = engine.generate_credentials("developer-role").await.unwrap();
        let user_ocid = credential.user_ocid.clone();

        engine.revoke_credentials(&user_ocid).await.unwrap();

        let credentials = engine.credentials.read().await;
        assert!(!credentials.contains_key(&user_ocid));
    }

    #[tokio::test]
    async fn test_rotate_api_key() {
        let engine = OCISecretsEngine::new();
        let config = create_test_config();
        let role = create_test_role();

        engine.configure(config).await.unwrap();
        engine.create_role(role).await.unwrap();

        let credential = engine.generate_credentials("developer-role").await.unwrap();
        let original_fingerprint = credential.api_key_fingerprint.clone();

        let rotated = engine.rotate_api_key(&credential.user_ocid).await.unwrap();

        assert_ne!(rotated.api_key_fingerprint, original_fingerprint);
        assert_eq!(rotated.user_ocid, credential.user_ocid);
    }
}
