//! AppRole Authentication
//!
//! Machine/application authentication using Role ID and Secret ID
//! with CIDR binding and secret ID constraints.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// AppRole authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AppRoleError {
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    
    #[error("Secret ID not found")]
    SecretIdNotFound,
    
    #[error("Secret ID expired")]
    SecretIdExpired,
    
    #[error("Secret ID uses exhausted")]
    SecretIdUsesExhausted,
    
    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),
    
    #[error("CIDR mismatch")]
    CidrMismatch,
    
    #[error("Invalid role ID")]
    InvalidRoleId,
}

/// AppRole configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleConfig {
    /// Role name
    pub name: String,
    
    /// Role ID (UUID)
    pub role_id: String,
    
    /// Bind to specific secret IDs
    pub bind_secret_id: bool,
    
    /// Bound CIDR list
    pub secret_id_bound_cidrs: Vec<String>,
    
    /// Secret ID TTL (seconds)
    pub secret_id_ttl: u64,
    
    /// Secret ID num uses (0 = unlimited)
    pub secret_id_num_uses: u32,
    
    /// Token TTL
    pub token_ttl: u64,
    
    /// Token max TTL
    pub token_max_ttl: u64,
    
    /// Token num uses (0 = unlimited)
    pub token_num_uses: u32,
    
    /// Policies
    pub policies: Vec<String>,
    
    /// Token bound CIDRs
    pub token_bound_cidrs: Vec<String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl AppRoleConfig {
    /// Create new role
    pub fn new(name: String) -> Self {
        Self {
            name,
            role_id: Uuid::new_v4().to_string(),
            bind_secret_id: true,
            secret_id_bound_cidrs: Vec::new(),
            secret_id_ttl: 0,
            secret_id_num_uses: 0,
            token_ttl: 3600,
            token_max_ttl: 86400,
            token_num_uses: 0,
            policies: Vec::new(),
            token_bound_cidrs: Vec::new(),
            created_at: Utc::now(),
        }
    }
}

/// Secret ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretId {
    pub secret_id: String,
    pub secret_id_accessor: String,
    pub role_name: String,
    pub metadata: HashMap<String, String>,
    pub cidr_list: Vec<String>,
    pub expiration: Option<DateTime<Utc>>,
    pub num_uses: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl SecretId {
    pub fn new(role_name: String, ttl: u64, num_uses: u32) -> Self {
        let expiration = if ttl > 0 {
            Some(Utc::now() + Duration::seconds(ttl as i64))
        } else {
            None
        };
        
        let num_uses = if num_uses > 0 { Some(num_uses) } else { None };
        
        Self {
            secret_id: Uuid::new_v4().to_string(),
            secret_id_accessor: Uuid::new_v4().to_string(),
            role_name,
            metadata: HashMap::new(),
            cidr_list: Vec::new(),
            expiration,
            num_uses,
            created_at: Utc::now(),
            last_used_at: None,
        }
    }
    
    pub fn is_expired(&self) -> bool {
        self.expiration.map(|exp| Utc::now() > exp).unwrap_or(false)
    }
    
    pub fn is_uses_exhausted(&self) -> bool {
        self.num_uses.map(|uses| uses == 0).unwrap_or(false)
    }
    
    pub fn consume_use(&mut self) {
        if let Some(ref mut uses) = self.num_uses {
            if *uses > 0 { *uses -= 1; }
        }
        self.last_used_at = Some(Utc::now());
    }
    
    pub fn check_cidr(&self, client_ip: &str) -> bool {
        if self.cidr_list.is_empty() { return true; }
        self.cidr_list.iter().any(|cidr| {
            if cidr.contains('/') {
                let parts: Vec<&str> = cidr.split('/').collect();
                client_ip.starts_with(parts[0])
            } else {
                cidr == client_ip
            }
        })
    }
}

/// AppRole authentication service
pub struct AppRoleAuth {
    roles: Arc<RwLock<HashMap<String, AppRoleConfig>>>,
    role_id_index: Arc<RwLock<HashMap<String, String>>>,
    secret_ids: Arc<RwLock<HashMap<String, SecretId>>>,
}

impl AppRoleAuth {
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
            role_id_index: Arc::new(RwLock::new(HashMap::new())),
            secret_ids: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn create_role(&self, role: AppRoleConfig) -> Result<(), AppRoleError> {
        let mut roles = self.roles.write().await;
        let mut index = self.role_id_index.write().await;
        index.insert(role.role_id.clone(), role.name.clone());
        roles.insert(role.name.clone(), role);
        Ok(())
    }
    
    pub async fn get_role(&self, name: &str) -> Option<AppRoleConfig> {
        let roles = self.roles.read().await;
        roles.get(name).cloned()
    }
    
    async fn get_role_by_id(&self, role_id: &str) -> Option<AppRoleConfig> {
        let index = self.role_id_index.read().await;
        let role_name = index.get(role_id)?;
        drop(index);
        self.get_role(role_name).await
    }
    
    pub async fn generate_secret_id(
        &self,
        role_name: &str,
        metadata: HashMap<String, String>,
        cidr_list: Vec<String>,
    ) -> Result<SecretId, AppRoleError> {
        let roles = self.roles.read().await;
        let role = roles.get(role_name)
            .ok_or_else(|| AppRoleError::RoleNotFound(role_name.to_string()))?;
        
        let mut secret_id = SecretId::new(
            role_name.to_string(),
            role.secret_id_ttl,
            role.secret_id_num_uses,
        );
        
        secret_id.metadata = metadata;
        secret_id.cidr_list = if cidr_list.is_empty() {
            role.secret_id_bound_cidrs.clone()
        } else {
            cidr_list
        };
        
        drop(roles);
        
        let mut secret_ids = self.secret_ids.write().await;
        secret_ids.insert(secret_id.secret_id.clone(), secret_id.clone());
        Ok(secret_id)
    }
    
    pub async fn login(
        &self,
        role_id: &str,
        secret_id: &str,
        client_ip: Option<&str>,
    ) -> Result<AppRoleLoginResponse, AppRoleError> {
        let role = self.get_role_by_id(role_id).await
            .ok_or(AppRoleError::InvalidRoleId)?;
        
        if role.bind_secret_id {
            let mut secret_ids = self.secret_ids.write().await;
            let mut secret = secret_ids.get_mut(secret_id)
                .ok_or(AppRoleError::SecretIdNotFound)?
                .clone();
            
            if secret.is_expired() {
                secret_ids.remove(secret_id);
                return Err(AppRoleError::SecretIdExpired);
            }
            
            if secret.is_uses_exhausted() {
                secret_ids.remove(secret_id);
                return Err(AppRoleError::SecretIdUsesExhausted);
            }
            
            if let Some(ip) = client_ip {
                if !secret.check_cidr(ip) {
                    return Err(AppRoleError::CidrMismatch);
                }
            }
            
            secret.consume_use();
            secret_ids.insert(secret_id.to_string(), secret.clone());
            
            if secret.is_uses_exhausted() {
                secret_ids.remove(secret_id);
            }
        }
        
        Ok(AppRoleLoginResponse {
            role_name: role.name,
            policies: role.policies,
            token_ttl: role.token_ttl,
            token_num_uses: role.token_num_uses,
        })
    }
    
    pub async fn list_secret_id_accessors(&self, role_name: &str) -> Vec<String> {
        let secret_ids = self.secret_ids.read().await;
        secret_ids.values()
            .filter(|s| s.role_name == role_name)
            .map(|s| s.secret_id_accessor.clone())
            .collect()
    }
    
    pub async fn destroy_secret_id(&self, accessor: &str) -> Result<(), AppRoleError> {
        let mut secret_ids = self.secret_ids.write().await;
        let secret_id = secret_ids.values()
            .find(|s| s.secret_id_accessor == accessor)
            .map(|s| s.secret_id.clone())
            .ok_or(AppRoleError::SecretIdNotFound)?;
        secret_ids.remove(&secret_id);
        Ok(())
    }
}

impl Default for AppRoleAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleLoginResponse {
    pub role_name: String,
    pub policies: Vec<String>,
    pub token_ttl: u64,
    pub token_num_uses: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_role() {
        let approle = AppRoleAuth::new();
        let mut role = AppRoleConfig::new("app1".to_string());
        role.policies = vec!["app1-policy".to_string()];
        approle.create_role(role).await.unwrap();
        let retrieved = approle.get_role("app1").await.unwrap();
        assert_eq!(retrieved.name, "app1");
    }
    
    #[tokio::test]
    async fn test_login() {
        let approle = AppRoleAuth::new();
        let mut role = AppRoleConfig::new("app1".to_string());
        role.policies = vec!["read".to_string()];
        let role_id = role.role_id.clone();
        approle.create_role(role).await.unwrap();
        
        let secret = approle.generate_secret_id("app1", HashMap::new(), Vec::new()).await.unwrap();
        let response = approle.login(&role_id, &secret.secret_id, None).await.unwrap();
        assert_eq!(response.role_name, "app1");
    }
}
