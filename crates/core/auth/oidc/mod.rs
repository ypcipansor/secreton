// OIDC Authentication Module
// OpenID Connect authentication for external identity providers

pub mod config;
pub mod validator;

// Remove separate tests module for now
// #[cfg(test)]
// mod tests;

pub use config::{OidcConfig, ClaimsMapping, JwtValidationConfig, UserProvisioningConfig};
pub use validator::{OidcValidator, ValidationResult, UserInfo, JwtClaims};

use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

use super::traits::{AuthMethod, AuthResult, Credentials, TokenInfo};
use crate::storage::{StorageEngine, StorageEntry};
use crate::audit::{AuditLogger, AuditLog, AuditStatus};
use anyhow::{Result, Context, anyhow};
use tracing::{info, debug};

/// OIDC-specific user structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OidcUser {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub oidc_subject: String,
    pub provider: String,
}

/// OIDC authentication credentials
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OidcCredentials {
    /// JWT token from OIDC provider
    pub jwt_token: String,
    /// Optional provider name for multiple OIDC configs
    pub provider: Option<String>,
    /// Additional context data
    pub context: HashMap<String, String>,
}

/// Cached user information
#[derive(Debug, Clone)]
struct CachedUser {
    user: OidcUser,
    user_info: UserInfo,
    cached_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// OIDC Authentication Engine
pub struct OidcAuth {
    config: OidcConfig,
    validator: OidcValidator,
    storage: Arc<dyn StorageEngine>,
    audit_logger: AuditLogger,
    user_cache: Arc<RwLock<HashMap<String, CachedUser>>>,
}

impl OidcAuth {
    /// Create a new OIDC Authentication instance
    pub fn new(
        config: OidcConfig,
        storage: Arc<dyn StorageEngine>,
        audit_logger: AuditLogger,
    ) -> Result<Self> {
        // Validate configuration
        config.validate().context("Invalid OIDC configuration")?;
        
        let validator = OidcValidator::new(config.clone());
        
        Ok(Self {
            config,
            validator,
            storage,
            audit_logger,
            user_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Authenticate user with OIDC JWT token
    async fn authenticate_with_token(&self, token: &str) -> Result<(OidcUser, UserInfo)> {
        debug!("Starting OIDC authentication with JWT token");
        
        // Validate JWT token
        let validation_result = self.validator.validate_token(token).await
            .context("Failed to validate JWT token")?;
            
        if !validation_result.is_valid {
            return Err(anyhow!("JWT token validation failed: {:?}", validation_result.validation_errors));
        }
        
        // Extract user information from claims
        let user_info = self.validator.extract_user_info(&validation_result.claims)
            .context("Failed to extract user information from JWT claims")?;
            
        debug!("Extracted user info: user_id={}, username={}", user_info.user_id, user_info.username);
        
        // Check user cache first
        if let Some(cached_user) = self.get_cached_user(&user_info.user_id).await? {
            if Utc::now() < cached_user.expires_at {
                debug!("Using cached user for: {}", user_info.user_id);
                return Ok((cached_user.user, cached_user.user_info));
            }
        }
        
        // Get or create user
        let user = self.get_or_create_user(&user_info).await
            .context("Failed to get or create user")?;
            
        // Cache the user
        self.cache_user(&user, &user_info).await?;
        
        info!("OIDC authentication successful for user: {} ({})", user_info.username, user_info.user_id);
        Ok((user, user_info))
    }

    /// Get or create user based on OIDC user info
    async fn get_or_create_user(&self, user_info: &UserInfo) -> Result<OidcUser> {
        let storage_key = format!("auth/oidc/users/{}", user_info.user_id);
        
        // Try to get existing user
        match self.storage.get(&storage_key).await {
            Ok(Some(entry)) => {
                let mut user: OidcUser = serde_json::from_slice(&entry.value)
                    .context("Failed to deserialize user data")?;
                
                // Update user attributes if configured
                if self.config.user_provisioning.update_user_attributes {
                    user = self.update_user_attributes(user, user_info)?;
                    
                    // Save updated user
                    let updated_entry = StorageEntry {
                        key: storage_key.clone(),
                        value: serde_json::to_vec(&user)?,
                        metadata: HashMap::new(),
                    };
                    
                    self.storage.put(updated_entry).await
                        .context("Failed to update user in storage")?;
                }
                
                debug!("Retrieved existing user: {}", user.username);
                Ok(user)
            },
            Ok(None) => {
                // Create new user if auto-creation is enabled
                if !self.config.user_provisioning.auto_create_users {
                    return Err(anyhow!("User does not exist and auto-creation is disabled"));
                }
                
                let user = self.create_new_user(user_info)?;
                
                // Save new user
                let entry = StorageEntry {
                    key: storage_key,
                    value: serde_json::to_vec(&user)?,
                    metadata: HashMap::new(),
                };
                
                self.storage.put(entry).await
                    .context("Failed to save new user to storage")?;
                
                info!("Created new OIDC user: {} ({})", user.username, user_info.user_id);
                Ok(user)
            },
            Err(e) => Err(anyhow!("Failed to query user storage: {}", e)),
        }
    }

    /// Create a new user from OIDC user info
    fn create_new_user(&self, user_info: &UserInfo) -> Result<OidcUser> {
        let policies = self.calculate_user_policies(user_info);
        
        let mut metadata = user_info.metadata.clone();
        metadata.insert("auth_method".to_string(), "oidc".to_string());
        metadata.insert("provider".to_string(), self.config.provider_name.clone());
        metadata.insert("oidc_subject".to_string(), user_info.user_id.clone());
        
        // Add groups and roles to metadata
        if !user_info.groups.is_empty() {
            metadata.insert("groups".to_string(), user_info.groups.join(","));
        }
        if !user_info.roles.is_empty() {
            metadata.insert("roles".to_string(), user_info.roles.join(","));
        }
        
        Ok(OidcUser {
            id: Uuid::new_v4().to_string(),
            username: user_info.username.clone(),
            email: user_info.email.clone(),
            display_name: user_info.metadata.get("name").cloned(),
            policies,
            metadata,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
            is_active: true,
            oidc_subject: user_info.user_id.clone(),
            provider: self.config.provider_name.clone(),
        })
    }

    /// Update user attributes from OIDC user info
    fn update_user_attributes(&self, mut user: OidcUser, user_info: &UserInfo) -> Result<OidcUser> {
        // Update basic attributes
        if user.email != user_info.email {
            user.email = user_info.email.clone();
        }
        
        if let Some(display_name) = user_info.metadata.get("name") {
            user.display_name = Some(display_name.clone());
        }
        
        // Update policies based on current groups/roles
        user.policies = self.calculate_user_policies(user_info);
        
        // Update metadata
        for field in &self.config.user_provisioning.user_metadata_fields {
            if let Some(value) = user_info.metadata.get(field) {
                user.metadata.insert(field.clone(), value.clone());
            }
        }
        
        // Update groups and roles in metadata
        if !user_info.groups.is_empty() {
            user.metadata.insert("groups".to_string(), user_info.groups.join(","));
        }
        if !user_info.roles.is_empty() {
            user.metadata.insert("roles".to_string(), user_info.roles.join(","));
        }
        
        user.updated_at = Utc::now();
        user.last_login = Some(Utc::now());
        
        Ok(user)
    }

    /// Calculate user policies based on groups and roles
    fn calculate_user_policies(&self, user_info: &UserInfo) -> Vec<String> {
        let mut policies = self.config.claims_mapping.default_policies.clone();
        
        // Add policies from groups
        for group in &user_info.groups {
            if let Some(group_policies) = self.config.claims_mapping.group_policies.get(group) {
                policies.extend(group_policies.clone());
            }
        }
        
        // Add policies from roles
        for role in &user_info.roles {
            if let Some(role_policies) = self.config.claims_mapping.role_policies.get(role) {
                policies.extend(role_policies.clone());
            }
        }
        
        // Remove duplicates and sort
        policies.sort();
        policies.dedup();
        policies
    }

    /// Check user cache
    async fn get_cached_user(&self, user_id: &str) -> Result<Option<CachedUser>> {
        let cache = self.user_cache.read().await;
        Ok(cache.get(user_id).cloned())
    }

    /// Cache user information
    async fn cache_user(&self, user: &OidcUser, user_info: &UserInfo) -> Result<()> {
        let cache_ttl = Duration::seconds(self.config.cache_settings.user_cache_ttl as i64);
        let cached_user = CachedUser {
            user: user.clone(),
            user_info: user_info.clone(),
            cached_at: Utc::now(),
            expires_at: Utc::now() + cache_ttl,
        };
        
        let mut cache = self.user_cache.write().await;
        cache.insert(user_info.user_id.clone(), cached_user);
        
        // Clean up expired entries
        let now = Utc::now();
        cache.retain(|_, cached| cached.expires_at > now);
        
        Ok(())
    }

    /// Get OIDC configuration for management endpoints
    pub fn get_config(&self) -> &OidcConfig {
        &self.config
    }

    /// Update OIDC configuration
    pub async fn update_config(&mut self, new_config: OidcConfig) -> Result<()> {
        new_config.validate().context("Invalid OIDC configuration")?;
        
        self.config = new_config.clone();
        self.validator = OidcValidator::new(new_config);
        
        // Clear caches to force refresh
        self.user_cache.write().await.clear();
        
        info!("OIDC configuration updated for provider: {}", self.config.provider_name);
        Ok(())
    }

    /// List configured providers
    pub fn list_providers(&self) -> Vec<String> {
        vec![self.config.provider_name.clone()]
    }

    /// Get provider statistics
    pub async fn get_provider_stats(&self) -> Result<ProviderStats> {
        let user_count = self.count_oidc_users().await?;
        let cache_size = self.user_cache.read().await.len();
        
        Ok(ProviderStats {
            provider_name: self.config.provider_name.clone(),
            user_count,
            cached_users: cache_size,
            discovery_url: self.config.discovery_url.to_string(),
            client_id: self.config.client_id.clone(),
        })
    }

    /// Count OIDC users in storage
    async fn count_oidc_users(&self) -> Result<usize> {
        // Use list method from StorageEngine
        let prefix = "auth/oidc/users/";
        let keys = self.storage.list(prefix).await
            .context("Failed to list OIDC user keys")?;
        Ok(keys.len())
    }
}

#[async_trait]
impl AuthMethod for OidcAuth {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResult> {
        match credentials {
            Credentials::Oidc { jwt_token, provider, context } => {
                let oidc_creds = OidcCredentials {
                    jwt_token: jwt_token.clone(),
                    provider: provider.clone(),
                    context: context.clone(),
                };
                self.authenticate_oidc_credentials(&oidc_creds).await
            },
            Credentials::Generic(value) => {
                // Try to parse as OIDC credentials
                let oidc_creds: OidcCredentials = serde_json::from_value(value.clone())
                    .context("Invalid OIDC credentials format")?;
                
                self.authenticate_oidc_credentials(&oidc_creds).await
            },
            _ => Err(anyhow!("OIDC authentication requires OIDC or Generic credentials with JWT token")),
        }
    }

    async fn validate_config(&self, config: &serde_json::Value) -> Result<()> {
        let _: OidcConfig = serde_json::from_value(config.clone())
            .context("Invalid OIDC configuration")?;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<String>> {
        // List OIDC users from storage
        let prefix = "auth/oidc/users/";
        let keys = self.storage.list(prefix).await
            .context("Failed to list OIDC users")?;
            
        let mut users = Vec::new();
        for key in keys {
            if let Some(_user_id) = key.strip_prefix(prefix) {
                // Try to get user data to extract username
                if let Ok(Some(entry)) = self.storage.get(&key).await {
                    if let Ok(user) = serde_json::from_slice::<OidcUser>(&entry.value) {
                        users.push(user.username);
                    }
                }
            }
        }
        
        Ok(users)
    }

    async fn create_user(&self, _username: &str, _config: &serde_json::Value) -> Result<()> {
        // OIDC users are auto-created during authentication
        Err(anyhow!("OIDC users are automatically created during authentication. Configure user provisioning settings instead."))
    }

    async fn delete_user(&self, username: &str) -> Result<()> {
        // Find user by username and delete
        let prefix = "auth/oidc/users/";
        let keys = self.storage.list(prefix).await
            .context("Failed to list OIDC users")?;
            
        for key in keys {
            if let Ok(Some(entry)) = self.storage.get(&key).await {
                if let Ok(user) = serde_json::from_slice::<OidcUser>(&entry.value) {
                    if user.username == username {
                        self.storage.delete(&key).await
                            .context("Failed to delete OIDC user")?;
                        
                        info!("Deleted OIDC user: {}", username);
                        return Ok(());
                    }
                }
            }
        }
        
        Err(anyhow!("OIDC user not found: {}", username))
    }

    fn name(&self) -> &'static str {
        "oidc"
    }

    fn description(&self) -> &'static str {
        "OpenID Connect authentication for external identity providers (Auth0, Okta, Azure AD)"
    }

    fn supports_user_management(&self) -> bool {
        true // We support listing and deleting OIDC users
    }

    fn supports_mfa(&self) -> bool {
        false // MFA is handled by the external OIDC provider
    }
}

impl OidcAuth {
    /// Internal method to authenticate OIDC credentials
    async fn authenticate_oidc_credentials(&self, credentials: &OidcCredentials) -> Result<AuthResult> {
        let start_time = Utc::now();
        
        // Authenticate with JWT token
        let (user, user_info) = self.authenticate_with_token(&credentials.jwt_token).await
            .context("OIDC authentication failed")?;
        
        // Create token info
        let token_info = TokenInfo {
            id: Uuid::new_v4().to_string(),
            policies: user.policies.clone(),
            metadata: user.metadata.clone(),
            ttl: self.config.user_provisioning.default_user_ttl,
            renewable: false, // OIDC tokens are typically not renewable through Vault
            entity_id: Some(user.id.clone()),
        };
        
        // Store token information
        let token_storage_key = format!("auth/oidc/tokens/{}", token_info.id);
        let token_entry = StorageEntry {
            key: token_storage_key.clone(),
            value: serde_json::to_vec(&token_info)?,
            metadata: HashMap::new(),
        };
        
        self.storage.put(token_entry).await
            .context("Failed to store token information")?;
        
        // Create audit log
        let mut audit_details = HashMap::new();
        audit_details.insert("provider".to_string(), self.config.provider_name.clone());
        audit_details.insert("user_id".to_string(), user_info.user_id.clone());
        audit_details.insert("username".to_string(), user.username.clone());
        audit_details.insert("auth_duration_ms".to_string(), 
                           Utc::now().signed_duration_since(start_time).num_milliseconds().to_string());
        
        if let Some(email) = &user.email {
            audit_details.insert("email".to_string(), email.clone());
        }
        
        let audit_log = AuditLog {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "oidc_authenticate".to_string(),
            actor: Some(user.username.clone()),
            resource_type: "user".to_string(),
            resource_id: user.id.clone(),
            status: AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata: audit_details,
        };
        
        self.audit_logger.log(audit_log).await?;
        
        Ok(AuthResult {
            success: true,
            token: Some(token_info),
            user_info: Some({
                let mut info = HashMap::new();
                info.insert("user_id".to_string(), serde_json::Value::String(user.id.clone()));
                info.insert("username".to_string(), serde_json::Value::String(user.username.clone()));
                info.insert("email".to_string(), serde_json::Value::String(user.email.clone().unwrap_or_default()));
                info.insert("provider".to_string(), serde_json::Value::String(self.config.provider_name.clone()));
                info.insert("oidc_subject".to_string(), serde_json::Value::String(user_info.user_id.clone()));
                info
            }),
            policies: user.policies.clone(),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("auth_method".to_string(), "oidc".to_string());
                meta.insert("provider".to_string(), self.config.provider_name.clone());
                meta.insert("auth_duration_ms".to_string(), 
                           Utc::now().signed_duration_since(start_time).num_milliseconds().to_string());
                meta
            },
            error: None,
        })
    }
}

/// Provider statistics
#[derive(Debug, Clone)]
pub struct ProviderStats {
    pub provider_name: String,
    pub user_count: usize,
    pub cached_users: usize,
    pub discovery_url: String,
    pub client_id: String,
}
