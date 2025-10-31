//! AppRole authentication method

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

/// AppRole authentication method
pub struct AppRoleAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    roles: RwLock<HashMap<String, AppRole>>,
}

impl AppRoleAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            roles: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new AppRole
    pub async fn create_role(
        &self,
        role_name: String,
        role_id: String,
        secret_id: String,
        policies: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> AuthMethodResult<()> {
        let role = AppRole {
            role_name: role_name.to_string(),
            role_id,
            secret_id,
            policies,
            metadata,
            bound_cidr_list: vec![],
            secret_id_ttl: None,
            token_ttl: None,
            token_max_ttl: None,
        };

        let mut roles = self.roles.write().await;
        roles.insert(role_name, role);
        Ok(())
    }

    /// Generate a secret ID for a role
    pub async fn generate_secret_id(&self, role_name: &str) -> AuthMethodResult<String> {
        let mut roles = self.roles.write().await;
        if let Some(role) = roles.get_mut(role_name) {
            let secret_id = Uuid::new_v4().to_string();
            role.secret_id = secret_id.to_string();
            Ok(secret_id)
        } else {
            Err(AuthMethodError::RoleNotFound(role_name.to_string()))
        }
    }
}

#[async_trait]
impl AuthMethodImpl for AppRoleAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::AppRole
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());
        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(AuthMethodError::MethodDisabled);
        }

        match credentials {
            AuthCredentials::AppRole { role_id, secret_id } => {
                // Find role by role_id
                let roles = self.roles.read().await;
                let role = roles.values().find(|r| r.role_id == *role_id).ok_or(
                    AuthMethodError::InvalidCredentials("Role not found".to_string()),
                )?;

                // Verify secret_id
                if role.secret_id != *secret_id {
                    return Err(AuthMethodError::InvalidCredentials(
                        "Invalid secret_id".to_string(),
                    ));
                }

                let user_info = UserInfo {
                    id: Uuid::new_v4(),
                    username: format!("approle-{}", role.role_name),
                    email: None,
                    display_name: Some(format!("AppRole {}", role.role_name)),
                    groups: vec![],
                    metadata: role.metadata.clone(),
                    created_at: Utc::now(),
                    last_login: Some(Utc::now()),
                };

                Ok(AuthResult {
                    authenticated: true,
                    user_info: Some(user_info),
                    token: None,
                    accessor: None,
                    mfa_required: false,
                    mfa_methods: vec![],
                    policies: role.policies.clone(),
                    lease_duration: role.token_ttl.map(|t| t as i64),
                    renewable: Some(true),
                    metadata: HashMap::new(),
                })
            }
            _ => Err(AuthMethodError::InvalidCredentials(
                "Unsupported credential type".to_string(),
            )),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(AuthMethodError::MethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(AuthMethodError::MethodNotSupported)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

/// AppRole configuration
#[derive(Clone, Debug)]
pub struct AppRole {
    pub role_name: String,
    pub role_id: String,
    pub secret_id: String,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub bound_cidr_list: Vec<String>,
    pub secret_id_ttl: Option<u64>,
    pub token_ttl: Option<u64>,
    pub token_max_ttl: Option<u64>,
}
