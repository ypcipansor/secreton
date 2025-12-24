//! Unified Dynamic Credentials Module
//!
//! This module provides a unified interface for generating and managing
//! dynamic credentials across different cloud providers and databases.
//! It consolidates the duplicated credential generation logic from various
//! integration modules.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use mysql_async::prelude::*;
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};

/// Unified credential types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    Database,
    Cloud,
}

/// Base credential structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicCredential {
    pub username: String,
    pub password: String,
    pub expires_at: String,
    pub credential_type: CredentialType,
    pub provider: String, // "mysql", "postgres", "aws", "gcp", etc.
    pub metadata: std::collections::HashMap<String, String>,
}

impl DynamicCredential {
    /// Create a new dynamic credential with default expiration (30 minutes)
    pub fn new(
        username: String,
        password: String,
        provider: &str,
        credential_type: CredentialType,
    ) -> Self {
        let expires_at = (Utc::now() + Duration::minutes(30)).to_rfc3339();
        Self {
            username,
            password,
            expires_at,
            credential_type,
            provider: provider.to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Create a credential with custom expiration
    pub fn with_expiration(
        username: String,
        password: String,
        provider: &str,
        credential_type: CredentialType,
        expires_in_minutes: i64,
    ) -> Self {
        let expires_at = (Utc::now() + Duration::minutes(expires_in_minutes)).to_rfc3339();
        Self {
            username,
            password,
            expires_at,
            credential_type,
            provider: provider.to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }
}

/// Trait for revocable credentials
#[async_trait]
pub trait RevocableCredential {
    /// Revoke this credential
    async fn revoke(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Trait for credential generators
#[async_trait]
pub trait CredentialGenerator {
    /// Generate a dynamic credential
    async fn generate_credential(
        &self,
        role: &str,
        options: &CredentialOptions,
    ) -> Result<DynamicCredential, Box<dyn std::error::Error + Send + Sync>>;
}

/// Options for credential generation
#[derive(Debug, Clone, Default)]
pub struct CredentialOptions {
    pub expires_in_minutes: Option<i64>,
    pub database_url: Option<String>,
    pub cloud_config: Option<CloudConfig>,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Cloud provider configuration
#[derive(Debug, Clone)]
pub enum CloudConfig {
    Aws {
        region: String,
        account_id: String,
        role_prefix: String,
    },
    Gcp {
        project_id: String,
        service_account_email: Option<String>,
    },
    Azure {
        subscription_id: String,
        tenant_id: String,
    },
}

/// MySQL credential generator
pub struct MySqlCredentialGenerator {
    pub mysql_url: String,
}

#[async_trait]
impl CredentialGenerator for MySqlCredentialGenerator {
    async fn generate_credential(
        &self,
        role: &str,
        options: &CredentialOptions,
    ) -> Result<DynamicCredential, Box<dyn std::error::Error + Send + Sync>> {
        let username = generate_username(role);
        let password = generate_password(16);
        let expires_in = options.expires_in_minutes.unwrap_or(30);

        // Create MySQL connection pool
        let pool = mysql_async::Pool::from_url(&self.mysql_url).unwrap();

        // Create user in MySQL
        let create_user_query = format!(
            "CREATE USER '{}'@'%' IDENTIFIED BY '{}' PASSWORD EXPIRE INTERVAL {} MINUTE",
            username, password, expires_in
        );

        let mut conn = pool.get_conn().await?;
        conn.query_drop(&create_user_query).await?;

        // Grant basic select permissions
        conn.query_drop(&format!("GRANT SELECT ON *.* TO '{}'@'%'", username))
            .await?;

        let mut credential = DynamicCredential::with_expiration(
            username,
            password,
            "mysql",
            CredentialType::Database,
            expires_in,
        );

        // Add connection URL to metadata
        credential
            .metadata
            .insert("connection_url".to_string(), self.mysql_url.clone());

        Ok(credential)
    }
}

/// AWS credential generator
pub struct AwsCredentialGenerator {
    pub region: String,
    pub account_id: String,
    pub role_prefix: String,
}

#[async_trait]
impl CredentialGenerator for AwsCredentialGenerator {
    async fn generate_credential(
        &self,
        role: &str,
        options: &CredentialOptions,
    ) -> Result<DynamicCredential, Box<dyn std::error::Error + Send + Sync>> {
        use aws_config::BehaviorVersion;
        use aws_sdk_sts::{Client, config::Region};

        let config = options.clone();
        let expires_in = config.expires_in_minutes.unwrap_or(30);

        let region = self.region.clone();

        let aws_config = aws_config::defaults(BehaviorVersion::v2025_08_07())
            .region(Region::new(region))
            .load()
            .await;

        let client = Client::new(&aws_config);

        let role_arn = format!("arn:aws:iam::{}:role/{}", self.account_id, role);

        let assume_role = client
            .assume_role()
            .role_arn(&role_arn)
            .role_session_name(format!("{}-session-{}", self.role_prefix, role))
            .set_duration_seconds(Some(expires_in as i32 * 60)) // Convert to seconds
            .send()
            .await
            .map_err(|e| format!("Failed to assume role: {}", e))?;

        let credentials = assume_role.credentials().ok_or("No credentials returned")?;

        let access_key = credentials.access_key_id();
        let secret_key = credentials.secret_access_key();
        let session_token = credentials.session_token();

        let _expires_at = credentials
            .expiration()
            .fmt(aws_sdk_sts::primitives::DateTimeFormat::DateTime)
            .unwrap();

        let username = generate_username(role);

        let mut credential = DynamicCredential::with_expiration(
            username,
            "".to_string(), // AWS credentials don't have a password
            "aws",
            CredentialType::Cloud,
            expires_in,
        );

        // Store AWS credentials in metadata
        credential
            .metadata
            .insert("access_key".to_string(), access_key.to_string());
        credential
            .metadata
            .insert("secret_key".to_string(), secret_key.to_string());
        credential
            .metadata
            .insert("session_token".to_string(), session_token.to_string());
        credential.metadata.insert("role_arn".to_string(), role_arn);
        credential
            .metadata
            .insert("region".to_string(), self.region.clone());

        Ok(credential)
    }
}

/// Unified credential manager
pub struct CredentialManager {
    generators: std::collections::HashMap<String, Box<dyn CredentialGenerator + Send + Sync>>,
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialManager {
    pub fn new() -> Self {
        Self {
            generators: std::collections::HashMap::new(),
        }
    }

    /// Register a credential generator for a provider
    pub fn register_generator(
        &mut self,
        provider: &str,
        generator: Box<dyn CredentialGenerator + Send + Sync>,
    ) {
        self.generators.insert(provider.to_string(), generator);
    }

    /// Generate a credential using the appropriate generator
    pub async fn generate_credential(
        &self,
        provider: &str,
        role: &str,
        options: &CredentialOptions,
    ) -> Result<DynamicCredential, Box<dyn std::error::Error + Send + Sync>> {
        let generator = self
            .generators
            .get(provider)
            .ok_or_else(|| format!("No generator registered for provider: {}", provider))?;

        generator.generate_credential(role, options).await
    }
}

/// Generate a random password
pub fn generate_password(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate a username with role and timestamp
pub fn generate_username(role: &str) -> String {
    format!("{}_{}", role, Utc::now().timestamp())
}

/// Default implementation for RevocableCredential that just logs
pub struct LoggingRevocableCredential {
    pub provider: String,
    pub identifier: String,
}

#[async_trait]
impl RevocableCredential for LoggingRevocableCredential {
    async fn revoke(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            "{} credential revoked for: {}",
            self.provider,
            self.identifier
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password() {
        let password = generate_password(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_username() {
        let username = generate_username("test-role");
        assert!(username.starts_with("test-role_"));
        assert!(username.len() > 10); // role + timestamp
    }

    #[test]
    fn test_dynamic_credential_creation() {
        let cred = DynamicCredential::new(
            "test-user".to_string(),
            "test-pass".to_string(),
            "test-provider",
            CredentialType::Database,
        );

        assert_eq!(cred.username, "test-user");
        assert_eq!(cred.password, "test-pass");
        assert_eq!(cred.provider, "test-provider");
        assert!(!cred.expires_at.is_empty());
    }
}
