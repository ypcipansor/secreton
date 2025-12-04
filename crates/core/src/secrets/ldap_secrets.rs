// LDAP Secrets Engine - OpenLDAP/FreeIPA dynamic credential rotation
use base64;
use chrono::{DateTime, Duration, Utc};
use secreton_common::utils::password::PasswordPolicy;
use secreton_errors::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// LDAP Secrets error types
#[derive(Debug, thiserror::Error)]
pub enum LDAPSecretsError {
    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Auth error: {0}")]
    AuthError(String),

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("LDIF error: {0}")]
    LDIFError(String),
}

pub type Result<T> = std::result::Result<T, LDAPSecretsError>;

impl From<LDAPSecretsError> for SecretonError {
    fn from(err: LDAPSecretsError) -> Self {
        match err {
            LDAPSecretsError::ConfigError(msg) => SecretonError::Configuration { message: msg },
            LDAPSecretsError::ConnectionError(msg) => SecretonError::ServiceUnavailable {
                service: format!("LDAP connection: {}", msg),
            },
            LDAPSecretsError::AuthError(msg) => SecretonError::Authentication { message: msg },
            LDAPSecretsError::RoleNotFound(name) => SecretonError::NotFound {
                resource: format!("LDAP role: {}", name),
            },
            LDAPSecretsError::UserNotFound(name) => SecretonError::NotFound {
                resource: format!("LDAP user: {}", name),
            },
            LDAPSecretsError::LDIFError(msg) => SecretonError::Validation {
                message: format!("LDIF error: {}", msg),
            },
        }
    }
}

/// LDIF operation types
#[derive(Debug)]
#[allow(dead_code)]
enum LDIFOperation {
    Add {
        dn: String,
        attributes: Vec<(String, HashSet<String>)>,
    },
    Modify {
        dn: String,
        modifications: Vec<ldap3::Mod<String>>,
    },
    Delete {
        dn: String,
    },
}

/// LDAP schema type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LDAPSchema {
    OpenLDAP,
    FreeIPA,
    ActiveDirectory,
}

/// LDAP Secrets configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDAPSecretsConfig {
    pub url: String,           // ldap://host:port
    pub bind_dn: String,       // Admin bind DN
    pub bind_password: String, // Admin password
    pub user_dn: String,       // Base DN for users
    pub password_policy: PasswordPolicy,
    pub schema: LDAPSchema,
    pub tls_enabled: bool,
    pub ca_cert: Option<String>,
}

/// LDAP role definition with LDIF templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDAPRole {
    pub name: String,
    pub creation_ldif: String,         // LDIF template for user creation
    pub deletion_ldif: String,         // LDIF for deletion
    pub rollback_ldif: Option<String>, // LDIF for rollback on error
    pub default_ttl: Duration,
    pub username_template: String, // Template for username generation
}

/// Password rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRotation {
    pub rotation_period: Duration,
    pub rotation_statements: Vec<String>, // LDIF modify statements
}

/// Generated LDAP user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDAPUser {
    pub username: String,
    pub password: String,
    pub dn: String, // Distinguished Name
    pub attributes: HashMap<String, Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_rotation: Option<DateTime<Utc>>,
}

/// LDAP Secrets engine
pub struct LDAPSecretsEngine {
    config: Arc<RwLock<Option<LDAPSecretsConfig>>>,
    roles: Arc<RwLock<HashMap<String, LDAPRole>>>,
    users: Arc<RwLock<HashMap<String, LDAPUser>>>,
}

impl LDAPSecretsEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            roles: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure LDAP connection
    pub async fn configure(&self, config: LDAPSecretsConfig) -> Result<()> {
        if config.url.is_empty() {
            return Err(LDAPSecretsError::ConfigError(
                "LDAP URL is required".to_string(),
            ));
        }
        if config.bind_dn.is_empty() {
            return Err(LDAPSecretsError::ConfigError(
                "Bind DN is required".to_string(),
            ));
        }

        // Validate connection and schema (mock)
        self.validate_connection(&config).await?;

        let mut cfg = self.config.write().await;
        *cfg = Some(config);

        Ok(())
    }

    /// Validate LDAP connection and schema
    async fn validate_connection(&self, config: &LDAPSecretsConfig) -> Result<()> {
        use ldap3::{LdapConnAsync, Scope};

        // Create LDAP connection
        let (_conn, mut ldap) = LdapConnAsync::new(&config.url).await.map_err(|e| {
            LDAPSecretsError::ConnectionError(format!("Failed to connect to LDAP: {}", e))
        })?;

        // Start TLS if enabled
        if config.tls_enabled {
            // ldap.starttls().await
            //     .map_err(|e| LDAPSecretsError::ConnectionError(format!("Failed to start TLS: {}", e)))?;
        }

        // Bind with credentials
        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await
            .map_err(|e| LDAPSecretsError::AuthError(format!("LDAP bind failed: {}", e)))?;

        // Verify bind was successful
        let search_result = ldap
            .search(&config.bind_dn, Scope::Base, "(objectClass=*)", vec!["dn"])
            .await
            .map_err(|e| LDAPSecretsError::ConnectionError(format!("LDAP search failed: {}", e)))?;

        if search_result.0.is_empty() {
            return Err(LDAPSecretsError::ConnectionError(
                "Bind DN verification failed - no results returned".to_string(),
            ));
        }

        // Verify user DN exists
        let user_search = ldap
            .search(&config.user_dn, Scope::Base, "(objectClass=*)", vec!["dn"])
            .await
            .map_err(|e| {
                LDAPSecretsError::ConfigError(format!(
                    "User DN '{}' does not exist: {}",
                    config.user_dn, e
                ))
            })?;

        if user_search.0.is_empty() {
            return Err(LDAPSecretsError::ConfigError(format!(
                "User DN '{}' does not exist",
                config.user_dn
            )));
        }

        // Unbind and close connection
        ldap.unbind()
            .await
            .map_err(|e| LDAPSecretsError::ConnectionError(format!("LDAP unbind failed: {}", e)))?;

        Ok(())
    }

    /// Create a role with LDIF templates
    pub async fn create_role(&self, role: LDAPRole) -> Result<()> {
        if role.name.is_empty() {
            return Err(LDAPSecretsError::ConfigError(
                "Role name is required".to_string(),
            ));
        }
        if role.creation_ldif.is_empty() {
            return Err(LDAPSecretsError::ConfigError(
                "Creation LDIF is required".to_string(),
            ));
        }

        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);

        Ok(())
    }

    /// Generate credentials from LDIF template
    pub async fn generate_credentials(&self, role_name: &str) -> Result<LDAPUser> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| LDAPSecretsError::ConfigError("LDAP not configured".to_string()))?;

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| LDAPSecretsError::RoleNotFound(role_name.to_string()))?;

        // Generate username from template
        let username = self.apply_template(&role.username_template);

        // Generate password
        let password = self.generate_password(&config.password_policy);

        // Generate DN
        let dn = format!("uid={},{}", username, config.user_dn);

        // Process creation LDIF
        let ldif = self.process_ldif(&role.creation_ldif, &username, &password, &dn)?;

        // Execute LDIF (mock)
        self.execute_ldif(config, &ldif).await?;

        let user = LDAPUser {
            username: username.clone(),
            password,
            dn: dn.clone(),
            attributes: HashMap::new(),
            created_at: Utc::now(),
            expires_at: Utc::now() + role.default_ttl,
            last_rotation: None,
        };

        // Store user
        let mut users = self.users.write().await;
        users.insert(username, user.clone());

        Ok(user)
    }

    /// Apply template variables
    fn apply_template(&self, template: &str) -> String {
        let random_suffix = uuid::Uuid::new_v4().to_string()[..8].to_string();
        template
            .replace("{{random}}", &random_suffix)
            .replace("{{timestamp}}", &Utc::now().timestamp().to_string())
    }

    /// Generate password according to policy
    fn generate_password(&self, policy: &PasswordPolicy) -> String {
        use rand::Rng;
        let length = policy.min_length.max(8) as usize;
        let mut rng = rand::thread_rng();

        // Build charset based on policy
        let mut charset = String::new();
        if policy.require_uppercase {
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if policy.require_lowercase {
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
        if policy.require_numbers {
            charset.push_str("0123456789");
        }
        if policy.require_special {
            if let Some(special) = &policy.allowed_special_chars {
                charset.push_str(special);
            } else {
                charset.push_str("!@#$%^&*");
            }
        }

        if charset.is_empty() {
            charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_string();
        }

        let charset_bytes = charset.as_bytes();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..charset_bytes.len());
                charset_bytes[idx] as char
            })
            .collect()
    }

    /// Process LDIF with variable substitution
    fn process_ldif(&self, ldif: &str, username: &str, password: &str, dn: &str) -> Result<String> {
        Ok(ldif
            .replace("{{username}}", username)
            .replace("{{password}}", password)
            .replace("{{dn}}", dn))
    }

    /// Execute LDIF operations
    async fn execute_ldif(&self, _config: &LDAPSecretsConfig, _ldif: &str) -> Result<()> {
        // Mock implementation - in real implementation would execute LDIF
        Ok(())
    }

    /// Parse LDIF content into operations
    #[allow(dead_code)]
    fn parse_ldif(&self, ldif: &str) -> Result<Vec<LDIFOperation>> {
        let mut operations = Vec::new();
        let lines: Vec<&str> = ldif.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }

            // Parse DN
            if line.starts_with("dn:") {
                let dn = line[3..].trim().to_string();

                // Check next line for changetype
                i += 1;
                if i >= lines.len() {
                    return Err(LDAPSecretsError::LDIFError(
                        "Incomplete LDIF entry".to_string(),
                    ));
                }

                let changetype_line = lines[i].trim();
                if changetype_line.starts_with("changetype:") {
                    let changetype = changetype_line[12..].trim();

                    match changetype {
                        "add" => {
                            let attributes = self.parse_ldif_attributes(&lines, &mut i)?;
                            operations.push(LDIFOperation::Add { dn, attributes });
                        }
                        "modify" => {
                            let modifications = self.parse_ldif_modifications(&lines, &mut i)?;
                            operations.push(LDIFOperation::Modify { dn, modifications });
                        }
                        "delete" => {
                            operations.push(LDIFOperation::Delete { dn });
                        }
                        _ => {
                            return Err(LDAPSecretsError::LDIFError(format!(
                                "Unsupported changetype: {}",
                                changetype
                            )));
                        }
                    }
                } else {
                    // Default to add operation
                    let attributes = self.parse_ldif_attributes(&lines, &mut i)?;
                    operations.push(LDIFOperation::Add { dn, attributes });
                }
            } else {
                i += 1;
            }
        }

        Ok(operations)
    }

    /// Parse LDIF attributes for add operations
    #[allow(dead_code)]
    fn parse_ldif_attributes(
        &self,
        lines: &[&str],
        i: &mut usize,
    ) -> Result<Vec<(String, HashSet<String>)>> {
        let mut attributes: HashMap<String, HashSet<String>> = HashMap::new();

        while *i < lines.len() {
            let line = lines[*i].trim();

            if line.is_empty() {
                *i += 1;
                break;
            }

            if line.starts_with('-') || line.contains("changetype:") {
                // End of attributes or start of modifications
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let attr_name = line[..colon_pos].trim().to_string();
                let attr_value =
                    if colon_pos + 1 < line.len() && line.chars().nth(colon_pos + 1) == Some(':') {
                        // Base64 encoded value
                        base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            &line[colon_pos + 2..].trim(),
                        )
                        .map_err(|e| LDAPSecretsError::LDIFError(format!("Invalid base64: {}", e)))?
                        .iter()
                        .map(|&b| b as char)
                        .collect::<String>()
                    } else {
                        line[colon_pos + 1..].trim().to_string()
                    };

                attributes
                    .entry(attr_name)
                    .or_insert_with(HashSet::new)
                    .insert(attr_value);
            }

            *i += 1;
        }

        Ok(attributes.into_iter().collect())
    }

    /// Parse LDIF modifications for modify operations
    fn parse_ldif_modifications(
        &self,
        lines: &[&str],
        i: &mut usize,
    ) -> Result<Vec<ldap3::Mod<String>>> {
        let mut modifications = Vec::new();

        while *i < lines.len() {
            let line = lines[*i].trim();

            if line.is_empty() {
                *i += 1;
                continue;
            }

            if line == "-" {
                // End of this modification
                *i += 1;
                continue;
            }

            if line.starts_with("add:")
                || line.starts_with("replace:")
                || line.starts_with("delete:")
            {
                let mod_type = &line[..line.find(':').unwrap()];
                let attr_name = line[line.find(':').unwrap() + 1..].trim().to_string();

                // Parse attribute values
                let mut values = Vec::new();
                *i += 1;

                while *i < lines.len() {
                    let value_line = lines[*i].trim();

                    if value_line.is_empty() || value_line == "-" {
                        break;
                    }

                    if let Some(colon_pos) = value_line.find(':') {
                        let value = value_line[colon_pos + 1..].trim().to_string();
                        values.push(value);
                    }

                    *i += 1;
                }

                let mod_op = match mod_type {
                    "add" => ldap3::Mod::Add(attr_name, HashSet::from_iter(values)),
                    "replace" => ldap3::Mod::Replace(attr_name, HashSet::from_iter(values)),
                    "delete" => ldap3::Mod::Delete(attr_name, HashSet::from_iter(values)),
                    _ => {
                        return Err(LDAPSecretsError::LDIFError(format!(
                            "Unknown modification type: {}",
                            mod_type
                        )));
                    }
                };

                modifications.push(mod_op);
            } else {
                *i += 1;
            }
        }

        Ok(modifications)
    }

    /// Rotate password for user
    pub async fn rotate_password(&self, username: &str) -> Result<String> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| LDAPSecretsError::ConfigError("LDAP not configured".to_string()))?;

        let mut users = self.users.write().await;
        let user = users
            .get_mut(username)
            .ok_or_else(|| LDAPSecretsError::UserNotFound(username.to_string()))?;

        // Generate new password
        let new_password = self.generate_password(&config.password_policy);

        // Create modify LDIF
        let modify_ldif = format!(
            "dn: {}\nchangetype: modify\nreplace: userPassword\nuserPassword: {}\n",
            user.dn, new_password
        );

        // Execute modification
        self.execute_ldif(config, &modify_ldif).await?;

        // Update user
        user.password = new_password.clone();
        user.last_rotation = Some(Utc::now());

        Ok(new_password)
    }

    /// Revoke credentials (delete user)
    pub async fn revoke_credentials(&self, username: &str) -> Result<()> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| LDAPSecretsError::ConfigError("LDAP not configured".to_string()))?;

        let users = self.users.read().await;
        let user = users
            .get(username)
            .ok_or_else(|| LDAPSecretsError::UserNotFound(username.to_string()))?;

        // Get role to find deletion LDIF
        let roles = self.roles.read().await;
        if let Some(role) = roles.values().next() {
            let deletion_ldif = self.process_ldif(&role.deletion_ldif, username, "", &user.dn)?;

            // Execute deletion
            self.execute_ldif(config, &deletion_ldif).await?;
        }

        drop(users);
        drop(roles);

        // Remove from local storage
        let mut users = self.users.write().await;
        users.remove(username);

        Ok(())
    }

    /// Rollback on error
    pub async fn rollback(&self, username: &str, role_name: &str) -> Result<()> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| LDAPSecretsError::ConfigError("LDAP not configured".to_string()))?;

        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| LDAPSecretsError::RoleNotFound(role_name.to_string()))?;

        if let Some(rollback_ldif) = &role.rollback_ldif {
            let users = self.users.read().await;
            let user = users
                .get(username)
                .ok_or_else(|| LDAPSecretsError::UserNotFound(username.to_string()))?;

            let ldif = self.process_ldif(rollback_ldif, username, "", &user.dn)?;

            // Execute rollback
            self.execute_ldif(config, &ldif).await?;
        }

        Ok(())
    }

    /// Get role
    pub async fn get_role(&self, name: &str) -> Result<LDAPRole> {
        let roles = self.roles.read().await;
        roles
            .get(name)
            .cloned()
            .ok_or_else(|| LDAPSecretsError::RoleNotFound(name.to_string()))
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
            .ok_or_else(|| LDAPSecretsError::RoleNotFound(name.to_string()))?;
        Ok(())
    }

    /// List managed users
    pub async fn list_managed_users(&self) -> Vec<String> {
        let users = self.users.read().await;
        users.keys().cloned().collect()
    }

    /// Get user
    pub async fn get_user(&self, username: &str) -> Result<LDAPUser> {
        let users = self.users.read().await;
        users
            .get(username)
            .cloned()
            .ok_or_else(|| LDAPSecretsError::UserNotFound(username.to_string()))
    }
}

impl Default for LDAPSecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> LDAPSecretsConfig {
        LDAPSecretsConfig {
            url: "ldap://localhost:389".to_string(),
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: "admin_password".to_string(),
            user_dn: "ou=users,dc=example,dc=com".to_string(),
            password_policy: PasswordPolicy {
                min_length: 24,
                max_length: None,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special: true,
                allowed_special_chars: Some("!@#$%^&*".to_string()),
            },
            schema: LDAPSchema::OpenLDAP,
            tls_enabled: false,
            ca_cert: None,
        }
    }

    #[tokio::test]
    async fn test_configure_ldap() {
        let engine = LDAPSecretsEngine::new();
        let config = create_test_config();

        engine.configure(config).await.unwrap();

        let cfg = engine.config.read().await;
        assert!(cfg.is_some());
        assert_eq!(cfg.as_ref().unwrap().schema, LDAPSchema::OpenLDAP);
    }

    #[tokio::test]
    async fn test_create_user_with_ldif() {
        let engine = LDAPSecretsEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let creation_ldif = r#"
dn: {{dn}}
changetype: add
objectClass: inetOrgPerson
objectClass: posixAccount
uid: {{username}}
cn: {{username}}
sn: Generated
userPassword: {{password}}
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/{{username}}
"#;

        let deletion_ldif = r#"
dn: {{dn}}
changetype: delete
"#;

        let role = LDAPRole {
            name: "app-user".to_string(),
            creation_ldif: creation_ldif.to_string(),
            deletion_ldif: deletion_ldif.to_string(),
            rollback_ldif: None,
            default_ttl: Duration::hours(24),
            username_template: "vault-{{random}}".to_string(),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("app-user").await.unwrap();

        assert!(user.username.starts_with("vault-"));
        assert_eq!(user.password.len(), 24);
        assert!(user.dn.contains(&user.username));
    }

    #[tokio::test]
    async fn test_password_rotation() {
        let engine = LDAPSecretsEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = LDAPRole {
            name: "rotate-test".to_string(),
            creation_ldif: "dn: {{dn}}\nchangetype: add\nuid: {{username}}\n".to_string(),
            deletion_ldif: "dn: {{dn}}\nchangetype: delete\n".to_string(),
            rollback_ldif: None,
            default_ttl: Duration::hours(12),
            username_template: "vault-{{random}}".to_string(),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("rotate-test").await.unwrap();
        let original_password = user.password.clone();
        let username = user.username.clone();

        // Rotate password
        let new_password = engine.rotate_password(&username).await.unwrap();

        assert_ne!(new_password, original_password);
        assert_eq!(new_password.len(), 24);

        let updated_user = engine.get_user(&username).await.unwrap();
        assert!(updated_user.last_rotation.is_some());
    }

    #[tokio::test]
    async fn test_revoke_with_deletion_ldif() {
        let engine = LDAPSecretsEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let role = LDAPRole {
            name: "temp-user".to_string(),
            creation_ldif: "dn: {{dn}}\nchangetype: add\nuid: {{username}}\n".to_string(),
            deletion_ldif: "dn: {{dn}}\nchangetype: delete\n".to_string(),
            rollback_ldif: None,
            default_ttl: Duration::hours(1),
            username_template: "vault-{{random}}".to_string(),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("temp-user").await.unwrap();
        let username = user.username.clone();

        // User should exist
        assert!(engine.get_user(&username).await.is_ok());

        // Revoke
        engine.revoke_credentials(&username).await.unwrap();

        // User should not exist
        assert!(engine.get_user(&username).await.is_err());
    }

    #[tokio::test]
    async fn test_rollback_on_error() {
        let engine = LDAPSecretsEngine::new();
        engine.configure(create_test_config()).await.unwrap();

        let rollback_ldif = r#"
dn: {{dn}}
changetype: modify
replace: description
description: Rolled back
"#;

        let role = LDAPRole {
            name: "rollback-test".to_string(),
            creation_ldif: "dn: {{dn}}\nchangetype: add\nuid: {{username}}\n".to_string(),
            deletion_ldif: "dn: {{dn}}\nchangetype: delete\n".to_string(),
            rollback_ldif: Some(rollback_ldif.to_string()),
            default_ttl: Duration::hours(1),
            username_template: "vault-{{random}}".to_string(),
        };

        engine.create_role(role).await.unwrap();

        let user = engine.generate_credentials("rollback-test").await.unwrap();
        let username = user.username.clone();

        // Execute rollback
        let result = engine.rollback(&username, "rollback-test").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_freeipa_schema() {
        let mut config = create_test_config();
        config.schema = LDAPSchema::FreeIPA;

        let engine = LDAPSecretsEngine::new();
        engine.configure(config).await.unwrap();

        let cfg = engine.config.read().await;
        assert_eq!(cfg.as_ref().unwrap().schema, LDAPSchema::FreeIPA);
    }

    #[tokio::test]
    async fn test_role_crud_operations() {
        let engine = LDAPSecretsEngine::new();

        let role = LDAPRole {
            name: "test-role".to_string(),
            creation_ldif: "dn: {{dn}}\nchangetype: add\n".to_string(),
            deletion_ldif: "dn: {{dn}}\nchangetype: delete\n".to_string(),
            rollback_ldif: None,
            default_ttl: Duration::hours(24),
            username_template: "user-{{random}}".to_string(),
        };

        // Create
        engine.create_role(role.clone()).await.unwrap();

        // Read
        let retrieved = engine.get_role("test-role").await.unwrap();
        assert_eq!(retrieved.name, "test-role");

        // List
        let roles = engine.list_roles().await;
        assert_eq!(roles.len(), 1);

        // Delete
        engine.delete_role("test-role").await.unwrap();
        assert!(engine.get_role("test-role").await.is_err());
    }
}
