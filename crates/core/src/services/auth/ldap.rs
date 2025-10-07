//! LDAP Authentication
//!
//! LDAP/Active Directory authentication with group mapping,
//! user search, and nested group support.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// LDAP authentication errors
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    #[error("LDAP bind failed: {0}")]
    BindFailed(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Group not found: {0}")]
    GroupNotFound(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
}

/// LDAP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (ldap:// or ldaps://)
    pub url: String,
    
    /// Base DN for user search
    pub user_dn: String,
    
    /// User attribute (e.g., "uid", "sAMAccountName")
    pub user_attr: String,
    
    /// Base DN for group search
    pub group_dn: String,
    
    /// Group filter
    pub group_filter: String,
    
    /// Group attribute (e.g., "cn")
    pub group_attr: String,
    
    /// Bind DN for search (optional)
    pub bind_dn: Option<String>,
    
    /// Bind password (optional)
    pub bind_password: Option<String>,
    
    /// Use TLS
    pub use_tls: bool,
    
    /// Certificate path for TLS
    pub certificate: Option<String>,
    
    /// Enable nested group search
    pub nested_groups: bool,
    
    /// Case sensitive username
    pub case_sensitive_names: bool,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: "ldap://localhost:389".to_string(),
            user_dn: "ou=users,dc=example,dc=com".to_string(),
            user_attr: "uid".to_string(),
            group_dn: "ou=groups,dc=example,dc=com".to_string(),
            group_filter: "(objectClass=groupOfNames)".to_string(),
            group_attr: "cn".to_string(),
            bind_dn: None,
            bind_password: None,
            use_tls: false,
            certificate: None,
            nested_groups: false,
            case_sensitive_names: false,
        }
    }
}

/// LDAP user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    /// Username
    pub username: String,
    
    /// Distinguished Name
    pub dn: String,
    
    /// Display name
    pub display_name: Option<String>,
    
    /// Email
    pub email: Option<String>,
    
    /// Groups (CNs)
    pub groups: Vec<String>,
    
    /// Additional attributes
    pub attributes: HashMap<String, Vec<String>>,
}

/// LDAP group mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapGroupMapping {
    /// LDAP group name
    pub ldap_group: String,
    
    /// Vault policies to assign
    pub policies: Vec<String>,
}

/// LDAP authentication service
pub struct LdapAuth {
    config: Arc<RwLock<LdapConfig>>,
    group_mappings: Arc<RwLock<HashMap<String, LdapGroupMapping>>>,
    connection_pool: Arc<RwLock<Vec<LdapConnection>>>,
}

/// LDAP connection (simulated)
#[derive(Debug, Clone)]
struct LdapConnection {
    url: String,
    connected_at: DateTime<Utc>,
    last_used: DateTime<Utc>,
}

impl LdapConnection {
    fn new(url: String) -> Self {
        Self {
            url,
            connected_at: Utc::now(),
            last_used: Utc::now(),
        }
    }
    
    async fn bind(&mut self, dn: &str, password: &str) -> Result<(), LdapError> {
        self.last_used = Utc::now();
        
        // Simulate LDAP bind operation
        if password.is_empty() {
            return Err(LdapError::BindFailed("Empty password".to_string()));
        }
        
        Ok(())
    }
    
    async fn search_user(
        &mut self,
        base_dn: &str,
        user_attr: &str,
        username: &str,
    ) -> Result<Option<LdapUser>, LdapError> {
        self.last_used = Utc::now();
        
        // Simulate LDAP search
        let dn = format!("{}={},{}", user_attr, username, base_dn);
        
        Ok(Some(LdapUser {
            username: username.to_string(),
            dn: dn.clone(),
            display_name: Some(format!("User {}", username)),
            email: Some(format!("{}@example.com", username)),
            groups: Vec::new(),
            attributes: HashMap::new(),
        }))
    }
    
    async fn search_groups(
        &mut self,
        base_dn: &str,
        user_dn: &str,
        nested: bool,
    ) -> Result<Vec<String>, LdapError> {
        self.last_used = Utc::now();
        
        // Simulate group search
        let mut groups = vec!["users".to_string()];
        
        // Simulate nested group search
        if nested {
            groups.push("all-users".to_string());
        }
        
        Ok(groups)
    }
}

impl LdapAuth {
    /// Create new LDAP auth service
    pub fn new(config: LdapConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            group_mappings: Arc::new(RwLock::new(HashMap::new())),
            connection_pool: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Get or create connection
    async fn get_connection(&self) -> Result<LdapConnection, LdapError> {
        let mut pool = self.connection_pool.write().await;
        let config = self.config.read().await;
        
        // Reuse existing connection if available
        if let Some(conn) = pool.first_mut() {
            let age = Utc::now() - conn.last_used;
            if age < Duration::minutes(5) {
                return Ok(conn.clone());
            }
        }
        
        // Create new connection
        let conn = LdapConnection::new(config.url.clone());
        pool.insert(0, conn.clone());
        
        // Keep pool size reasonable
        if pool.len() > 10 {
            pool.truncate(10);
        }
        
        Ok(conn)
    }
    
    /// Authenticate user
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LdapUser, LdapError> {
        let config = self.config.read().await;
        let mut conn = self.get_connection().await?;
        
        // Normalize username if needed
        let username = if config.case_sensitive_names {
            username.to_string()
        } else {
            username.to_lowercase()
        };
        
        // If bind DN is configured, bind as service account first
        if let (Some(bind_dn), Some(bind_password)) = 
            (&config.bind_dn, &config.bind_password) {
            conn.bind(bind_dn, bind_password).await?;
        }
        
        // Search for user
        let mut user = conn.search_user(
            &config.user_dn,
            &config.user_attr,
            &username,
        ).await?
            .ok_or_else(|| LdapError::UserNotFound(username.clone()))?;
        
        // Bind as user to verify password
        conn.bind(&user.dn, password).await?;
        
        // Search for groups
        let groups = conn.search_groups(
            &config.group_dn,
            &user.dn,
            config.nested_groups,
        ).await?;
        
        user.groups = groups;
        
        drop(config);
        
        Ok(user)
    }
    
    /// Add group mapping
    pub async fn add_group_mapping(
        &self,
        ldap_group: String,
        policies: Vec<String>,
    ) {
        let mut mappings = self.group_mappings.write().await;
        mappings.insert(ldap_group.clone(), LdapGroupMapping {
            ldap_group,
            policies,
        });
    }
    
    /// Get policies for user based on group mappings
    pub async fn get_user_policies(&self, user: &LdapUser) -> Vec<String> {
        let mappings = self.group_mappings.read().await;
        let mut policies = HashSet::new();
        
        for group in &user.groups {
            if let Some(mapping) = mappings.get(group) {
                policies.extend(mapping.policies.iter().cloned());
            }
        }
        
        policies.into_iter().collect()
    }
    
    /// Update configuration
    pub async fn update_config(&self, config: LdapConfig) {
        let mut current = self.config.write().await;
        *current = config;
        
        // Clear connection pool on config change
        let mut pool = self.connection_pool.write().await;
        pool.clear();
    }
    
    /// Get current configuration
    pub async fn get_config(&self) -> LdapConfig {
        let config = self.config.read().await;
        config.clone()
    }
    
    /// List group mappings
    pub async fn list_group_mappings(&self) -> Vec<LdapGroupMapping> {
        let mappings = self.group_mappings.read().await;
        mappings.values().cloned().collect()
    }
    
    /// Remove group mapping
    pub async fn remove_group_mapping(&self, ldap_group: &str) {
        let mut mappings = self.group_mappings.write().await;
        mappings.remove(ldap_group);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ldap_authenticate() {
        let config = LdapConfig::default();
        let ldap = LdapAuth::new(config);
        
        let result = ldap.authenticate("testuser", "password123").await;
        assert!(result.is_ok());
        
        let user = result.unwrap();
        assert_eq!(user.username, "testuser");
        assert!(!user.groups.is_empty());
    }
    
    #[tokio::test]
    async fn test_group_mapping() {
        let config = LdapConfig::default();
        let ldap = LdapAuth::new(config);
        
        ldap.add_group_mapping(
            "admins".to_string(),
            vec!["admin".to_string(), "write".to_string()],
        ).await;
        
        ldap.add_group_mapping(
            "users".to_string(),
            vec!["read".to_string()],
        ).await;
        
        let user = ldap.authenticate("testuser", "password123").await.unwrap();
        let policies = ldap.get_user_policies(&user).await;
        
        assert!(policies.contains(&"read".to_string()));
    }
    
    #[tokio::test]
    async fn test_case_sensitivity() {
        let mut config = LdapConfig::default();
        config.case_sensitive_names = false;
        let ldap = LdapAuth::new(config);
        
        let user1 = ldap.authenticate("TestUser", "password123").await.unwrap();
        assert_eq!(user1.username, "testuser");
    }
}
