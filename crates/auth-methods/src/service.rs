//! Authentication service orchestration

use crate::error::*;
use crate::model::*;
use async_trait::async_trait;
use secreton_errors::SecretonError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Core trait for authentication methods
#[async_trait]
pub trait AuthMethodImpl: Send + Sync {
    /// Get the method type
    fn method_type(&self) -> AuthMethodType;

    /// Initialize the authentication method
    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()>;

    /// Authenticate using this method
    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult>;

    /// Validate a token issued by this method
    async fn validate_token(&self, token: &str) -> AuthMethodResult<UserInfo>;

    /// Revoke a token issued by this method
    async fn revoke_token(&self, token: &str) -> AuthMethodResult<()>;

    /// Check if the method is enabled
    fn is_enabled(&self) -> bool;

    /// Enable the method
    fn enable(&mut self);

    /// Disable the method
    fn disable(&mut self);
}

/// Authentication method registry
pub struct AuthMethodRegistry {
    methods: HashMap<String, Arc<dyn AuthMethodImpl>>,
}

impl AuthMethodRegistry {
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: String, method: Arc<dyn AuthMethodImpl>) {
        self.methods.insert(name, method);
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn AuthMethodImpl>> {
        self.methods.get(name)
    }

    pub fn list(&self) -> Vec<String> {
        self.methods.keys().cloned().collect()
    }

    pub fn remove(&mut self, name: &str) -> Option<Arc<dyn AuthMethodImpl>> {
        self.methods.remove(name)
    }
}

/// Main authentication method service
pub struct AuthMethodService {
    registry: RwLock<AuthMethodRegistry>,
}

impl AuthMethodService {
    pub fn new() -> Self {
        Self {
            registry: RwLock::new(AuthMethodRegistry::new()),
        }
    }

    /// Register an authentication method
    pub async fn register_method(&self, name: String, method: Arc<dyn AuthMethodImpl>) {
        let mut registry = self.registry.write().await;
        registry.register(name, method);
    }

    /// Authenticate using a specific method
    pub async fn authenticate(
        &self,
        method_name: &str,
        credentials: &AuthCredentials,
    ) -> AuthMethodResult<AuthResult> {
        let registry = self.registry.read().await;
        let method = registry
            .get(method_name)
            .ok_or_else(|| SecretonError::NotFound {
                resource: format!("auth-method:{}", method_name),
            })?;

        method.authenticate(credentials).await
    }

    /// Login using login request
    pub async fn login(&self, request: &LoginRequest) -> AuthMethodResult<LoginResponse> {
        let auth_result = self
            .authenticate(&request.method, &request.credentials)
            .await?;

        // Check if MFA is required
        let _mfa_required = auth_result.mfa_required && request.mfa_code.is_none();

        let response = LoginResponse {
            auth: auth_result,
            warnings: vec![],
        };

        Ok(response)
    }

    /// Validate a token
    pub async fn validate_token(
        &self,
        method_name: &str,
        token: &str,
    ) -> AuthMethodResult<UserInfo> {
        let registry = self.registry.read().await;
        let method = registry
            .get(method_name)
            .ok_or_else(|| SecretonError::NotFound {
                resource: format!("auth-method:{}", method_name),
            })?;

        method.validate_token(token).await
    }

    /// Revoke a token
    pub async fn revoke_token(&self, method_name: &str, token: &str) -> AuthMethodResult<()> {
        let registry = self.registry.read().await;
        let method = registry
            .get(method_name)
            .ok_or_else(|| SecretonError::NotFound {
                resource: format!("auth-method:{}", method_name),
            })?;

        method.revoke_token(token).await
    }

    /// List available authentication methods
    pub async fn list_methods(&self) -> Vec<String> {
        let registry = self.registry.read().await;
        registry.list()
    }
}

impl Default for AuthMethodService {
    fn default() -> Self {
        Self::new()
    }
}
