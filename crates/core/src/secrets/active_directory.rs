// Active Directory Secrets Engine - Dynamic AD credential management
use chrono::{DateTime, Duration, Utc};
use ldap3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ADError {
    #[error("Active Directory error: {0}")]
    ADError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("Account not found: {0}")]
    NotFound(String),
    #[error("Role not found: {0}")]
    RoleNotFound(String),
}

pub type Result<T> = std::result::Result<T, ADError>;

/// Account type in Active Directory
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccountType {
    User,
    ServiceAccount,
    Computer,
}

/// Active Directory configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ADConfig {
    pub domain: String,
    pub url: String, // LDAP URL
    pub bind_dn: String,
    pub bind_password: String,
    pub service_account_ou: String, // OU for service accounts
    pub user_ou: String,            // OU for users
    pub tls_enabled: bool,
    pub certificate_path: Option<String>,
}

/// AD role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ADRole {
    pub name: String,
    pub service_account_name_template: String, // e.g., "vault-{{random}}"
    pub account_type: AccountType,
    pub distinguished_names: Vec<String>, // OUs where accounts can be created
    pub groups: Vec<String>,              // Groups to add account to
    pub ttl: Duration,
    pub max_ttl: Duration,
    pub created_at: DateTime<Utc>,
}

/// Generated AD account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ADAccount {
    pub username: String,
    pub password: String,
    pub distinguished_name: String,
    pub account_type: AccountType,
    pub groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ttl: Duration,
    pub role_name: String,
}

/// AD credentials response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ADCredentials {
    pub username: String,
    pub password: String,
    pub current_password: Option<String>, // For rotation
}

/// Group membership operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupOperation {
    Add,
    Remove,
}

/// Active Directory secrets engine
pub struct ActiveDirectoryEngine {
    config: Arc<RwLock<Option<ADConfig>>>,
    roles: Arc<RwLock<HashMap<String, ADRole>>>,
    accounts: Arc<RwLock<HashMap<String, ADAccount>>>,
    // Mock LDAP connection for testing
    ldap_connected: Arc<RwLock<bool>>,
}

impl ActiveDirectoryEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            accounts: Arc::new(RwLock::new(HashMap::new())),
            ldap_connected: Arc::new(RwLock::new(false)),
        }
    }

    /// Configure Active Directory connection
    pub async fn configure(&self, config: ADConfig) -> Result<()> {
        // Validate configuration
        if config.domain.is_empty() {
            return Err(ADError::ConfigError("Domain is required".to_string()));
        }
        if config.url.is_empty() {
            return Err(ADError::ConfigError("URL is required".to_string()));
        }
        if config.bind_dn.is_empty() {
            return Err(ADError::ConfigError("Bind DN is required".to_string()));
        }

        // Test connection (mock)
        self.test_connection(&config).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        let mut connected = self.ldap_connected.write().await;
        *connected = true;

        Ok(())
    }

    /// Test Active Directory connection
    pub async fn test_connection(&self, config: &ADConfig) -> Result<()> {
        use ldap3::{LdapConnAsync, LdapConnSettings, Scope};

        // Create LDAP connection
        let (conn, mut ldap) = if config.tls_enabled {
            LdapConnAsync::with_settings(LdapConnSettings::new().set_starttls(true), &config.url)
                .await
        } else {
            LdapConnAsync::new(&config.url).await
        }
        .map_err(|e| ADError::ADError(format!("Failed to connect to AD: {}", e)))?;

        // Start TLS if enabled - Note: StartTLS is now handled in connection settings above

        // Bind with credentials
        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await
            .map_err(|e| ADError::AuthError(format!("AD bind failed: {}", e)))?;

        // Verify bind was successful by searching for the domain
        let search_result = ldap
            .search(&config.bind_dn, Scope::Base, "(objectClass=*)", vec!["dn"])
            .await
            .map_err(|e| ADError::ADError(format!("AD search failed: {}", e)))?;

        if search_result.0.is_empty() {
            return Err(ADError::ADError(
                "Bind DN verification failed - no results returned".to_string(),
            ));
        }

        // Test access to user and service account OUs
        for ou in &[&config.user_ou, &config.service_account_ou] {
            let ou_search = ldap
                .search(
                    ou,
                    Scope::Base,
                    "(objectClass=organizationalUnit)",
                    vec!["dn"],
                )
                .await
                .map_err(|e| ADError::ConfigError(format!("OU '{}' not accessible: {}", ou, e)))?;

            if ou_search.0.is_empty() {
                return Err(ADError::ConfigError(format!("OU '{}' does not exist", ou)));
            }
        }

        // Unbind and close connection
        ldap.unbind()
            .await
            .map_err(|e| ADError::ADError(format!("AD unbind failed: {}", e)))?;

        Ok(())
    }

    /// Create an AD role
    pub async fn create_role(&self, role: ADRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(ADError::ConfigError("Role name is required".to_string()));
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Get AD role
    pub async fn get_role(&self, name: &str) -> Result<ADRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| ADError::RoleNotFound(name.to_string()))
    }

    /// List all roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }

    /// Generate dynamic AD credentials
    pub async fn generate_credentials(&self, role_name: &str) -> Result<ADCredentials> {
        let role = self.get_role(role_name).await?;

        // Check if AD is configured
        let config = self.config.read().await;
        if config.is_none() {
            return Err(ADError::ConfigError("AD not configured".to_string()));
        }

        // Generate username from template
        let username = self.generate_username(&role.service_account_name_template)?;

        // Generate secure password
        let password = self.generate_password();

        // Determine OU based on account type
        let config_ref = config.as_ref().unwrap();
        let ou = match role.account_type {
            AccountType::ServiceAccount => &config_ref.service_account_ou,
            AccountType::User => &config_ref.user_ou,
            AccountType::Computer => &config_ref.service_account_ou,
        };

        let distinguished_name = format!("CN={},{}", username, ou);

        // Create account in AD (mock)
        self.create_ad_account(&username, &password, &distinguished_name)
            .await?;

        // Add to groups
        for group in &role.groups {
            self.add_to_group(&username, group).await?;
        }

        // Store account
        let account = ADAccount {
            username: username.clone(),
            password: password.clone(),
            distinguished_name,
            account_type: role.account_type.clone(),
            groups: role.groups.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + role.ttl,
            ttl: role.ttl,
            role_name: role_name.to_string(),
        };

        let mut accounts = self.accounts.write().await;
        accounts.insert(username.clone(), account);

        Ok(ADCredentials {
            username,
            password,
            current_password: None,
        })
    }

    /// Generate username from template
    fn generate_username(&self, template: &str) -> Result<String> {
        // Replace {{random}} with random string
        let random = uuid::Uuid::new_v4()
            .to_string()
            .chars()
            .take(8)
            .collect::<String>();

        let username = template.replace("{{random}}", &random);
        Ok(username)
    }

    /// Generate secure password
    fn generate_password(&self) -> String {
        use rand::Rng;
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();
        (0..24)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Create account in Active Directory
    async fn create_ad_account(
        &self,
        _username: &str,
        _password: &str,
        _distinguished_name: &str,
    ) -> Result<()> {
        // Mock implementation - in real implementation would use LDAP
        Ok(())
    }

    /// Add account to group
    async fn add_to_group(&self, _username: &str, _group: &str) -> Result<()> {
        // Mock group membership
        // In real implementation, this would modify group membership in AD
        Ok(())
    }

    /// Rotate service account password
    pub async fn rotate_credentials(&self, username: &str) -> Result<ADCredentials> {
        let mut accounts = self.accounts.write().await;
        let account = accounts
            .get_mut(username)
            .ok_or_else(|| ADError::NotFound(username.to_string()))?;

        let current_password = account.password.clone();
        let new_password = self.generate_password();

        // Update password in AD (mock)
        self.update_ad_password(username, &new_password).await?;

        account.password = new_password.clone();

        Ok(ADCredentials {
            username: username.to_string(),
            password: new_password,
            current_password: Some(current_password),
        })
    }

    /// Update password in Active Directory
    async fn update_ad_password(&self, _username: &str, _new_password: &str) -> Result<()> {
        // Mock implementation
        Ok(())
    }

    /// Revoke AD credentials
    pub async fn revoke_credentials(&self, username: &str) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        let account = accounts
            .remove(username)
            .ok_or_else(|| ADError::NotFound(username.to_string()))?;

        // Delete account from AD
        self.delete_ad_account(&account.distinguished_name).await?;

        Ok(())
    }

    /// Delete account from Active Directory
    async fn delete_ad_account(&self, _distinguished_name: &str) -> Result<()> {
        // Mock implementation
        Ok(())
    }

    /// Manage group memberships
    pub async fn manage_groups(
        &self,
        username: &str,
        groups: Vec<String>,
        operation: GroupOperation,
    ) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        let account = accounts
            .get_mut(username)
            .ok_or_else(|| ADError::NotFound(username.to_string()))?;

        match operation {
            GroupOperation::Add => {
                for group in groups {
                    if !account.groups.contains(&group) {
                        account.groups.push(group.clone());
                        self.add_to_group(username, &group).await?;
                    }
                }
            }
            GroupOperation::Remove => {
                for group in groups {
                    account.groups.retain(|g| g != &group);
                    self.remove_from_group(username, &group).await?;
                }
            }
        }

        Ok(())
    }

    /// Remove account from group
    async fn remove_from_group(&self, _username: &str, _group: &str) -> Result<()> {
        // Mock group removal
        Ok(())
    }

    /// List generated accounts
    pub async fn list_accounts(&self) -> Vec<String> {
        let accounts = self.accounts.read().await;
        accounts.keys().cloned().collect()
    }

    /// Get account details
    pub async fn get_account(&self, username: &str) -> Result<ADAccount> {
        let accounts = self.accounts.read().await;
        accounts
            .get(username)
            .cloned()
            .ok_or_else(|| ADError::NotFound(username.to_string()))
    }

    /// Check if configuration exists
    pub async fn is_configured(&self) -> bool {
        let config = self.config.read().await;
        config.is_some()
    }
}

impl Default for ActiveDirectoryEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ADConfig {
        ADConfig {
            domain: "example.com".to_string(),
            url: "ldap://dc.example.com:389".to_string(),
            bind_dn: "CN=vault,CN=Users,DC=example,DC=com".to_string(),
            bind_password: "password123".to_string(),
            service_account_ou: "OU=ServiceAccounts,DC=example,DC=com".to_string(),
            user_ou: "OU=Users,DC=example,DC=com".to_string(),
            tls_enabled: true,
            certificate_path: None,
        }
    }

    #[tokio::test]
    async fn test_configure_ad() {
        let engine = ActiveDirectoryEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        assert!(engine.is_configured().await);
    }

    #[tokio::test]
    async fn test_create_role() {
        let engine = ActiveDirectoryEngine::new();

        let role = ADRole {
            name: "app-service".to_string(),
            service_account_name_template: "vault-{{random}}".to_string(),
            account_type: AccountType::ServiceAccount,
            distinguished_names: vec!["OU=ServiceAccounts,DC=example,DC=com".to_string()],
            groups: vec!["AppUsers".to_string()],
            ttl: Duration::hours(24),
            max_ttl: Duration::days(7),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let retrieved = engine.get_role("app-service").await.unwrap();
        assert_eq!(retrieved.name, "app-service");
        assert_eq!(retrieved.account_type, AccountType::ServiceAccount);
    }

    #[tokio::test]
    async fn test_generate_credentials() {
        let engine = ActiveDirectoryEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let role = ADRole {
            name: "webapp".to_string(),
            service_account_name_template: "vault-{{random}}".to_string(),
            account_type: AccountType::ServiceAccount,
            distinguished_names: vec!["OU=ServiceAccounts,DC=example,DC=com".to_string()],
            groups: vec!["WebAppGroup".to_string()],
            ttl: Duration::hours(8),
            max_ttl: Duration::days(1),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let creds = engine.generate_credentials("webapp").await.unwrap();

        assert!(creds.username.starts_with("vault-"));
        assert!(!creds.password.is_empty());
        assert_eq!(creds.password.len(), 24);
    }

    #[tokio::test]
    async fn test_rotate_credentials() {
        let engine = ActiveDirectoryEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let role = ADRole {
            name: "db-service".to_string(),
            service_account_name_template: "vault-{{random}}".to_string(),
            account_type: AccountType::ServiceAccount,
            distinguished_names: vec!["OU=ServiceAccounts,DC=example,DC=com".to_string()],
            groups: vec![],
            ttl: Duration::hours(12),
            max_ttl: Duration::days(3),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let initial_creds = engine.generate_credentials("db-service").await.unwrap();
        let initial_password = initial_creds.password.clone();

        let rotated_creds = engine
            .rotate_credentials(&initial_creds.username)
            .await
            .unwrap();

        assert_ne!(rotated_creds.password, initial_password);
        assert_eq!(rotated_creds.current_password.unwrap(), initial_password);
    }

    #[tokio::test]
    async fn test_revoke_credentials() {
        let engine = ActiveDirectoryEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let role = ADRole {
            name: "temp-service".to_string(),
            service_account_name_template: "vault-{{random}}".to_string(),
            account_type: AccountType::ServiceAccount,
            distinguished_names: vec!["OU=ServiceAccounts,DC=example,DC=com".to_string()],
            groups: vec![],
            ttl: Duration::hours(1),
            max_ttl: Duration::hours(2),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let creds = engine.generate_credentials("temp-service").await.unwrap();

        // Verify account exists
        let accounts = engine.list_accounts().await;
        assert!(accounts.contains(&creds.username));

        // Revoke
        engine.revoke_credentials(&creds.username).await.unwrap();

        // Verify account removed
        let accounts = engine.list_accounts().await;
        assert!(!accounts.contains(&creds.username));
    }

    #[tokio::test]
    async fn test_manage_groups() {
        let engine = ActiveDirectoryEngine::new();
        let config = create_test_config();
        engine.configure(config).await.unwrap();

        let role = ADRole {
            name: "app-user".to_string(),
            service_account_name_template: "vault-{{random}}".to_string(),
            account_type: AccountType::User,
            distinguished_names: vec!["OU=Users,DC=example,DC=com".to_string()],
            groups: vec!["BaseGroup".to_string()],
            ttl: Duration::hours(24),
            max_ttl: Duration::days(7),
            created_at: Utc::now(),
        };

        engine.create_role(role).await.unwrap();

        let creds = engine.generate_credentials("app-user").await.unwrap();

        // Add groups
        engine
            .manage_groups(
                &creds.username,
                vec!["AdminGroup".to_string(), "PowerUsers".to_string()],
                GroupOperation::Add,
            )
            .await
            .unwrap();

        let account = engine.get_account(&creds.username).await.unwrap();
        assert!(account.groups.contains(&"BaseGroup".to_string()));
        assert!(account.groups.contains(&"AdminGroup".to_string()));
        assert!(account.groups.contains(&"PowerUsers".to_string()));

        // Remove group
        engine
            .manage_groups(
                &creds.username,
                vec!["AdminGroup".to_string()],
                GroupOperation::Remove,
            )
            .await
            .unwrap();

        let account = engine.get_account(&creds.username).await.unwrap();
        assert!(!account.groups.contains(&"AdminGroup".to_string()));
        assert!(account.groups.contains(&"PowerUsers".to_string()));
    }
}
