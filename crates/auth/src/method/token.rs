//! Token-based authentication method

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use crate::model::*;
use crate::service::*;

/// Token authentication method
pub struct TokenAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    tokens: RwLock<HashMap<String, TokenInfo>>,
}

impl TokenAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a new token
    fn generate_token(&self) -> String {
        Uuid::new_v4().to_string()
    }

    /// Store token information
    async fn store_token(&self, token: String, info: TokenInfo) {
        let mut tokens = self.tokens.write().await;
        tokens.insert(token, info);
    }

    /// Retrieve token information
    async fn get_token_info(&self, token: &str) -> Option<TokenInfo> {
        let tokens = self.tokens.read().await;
        tokens.get(token).cloned()
    }

    /// Remove token
    async fn remove_token(&self, token: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token);
    }
}

#[async_trait]
impl AuthMethodImpl for TokenAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Token
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.to_string());
        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(SecretonError::MethodDisabled);
        }

        match credentials {
            AuthCredentials::Token { token } => {
                if let Some(token_info) = self.get_token_info(token).await {
                    if token_info.is_expired() {
                        return Err(SecretonError::TokenExpired);
                    }

                    let user_info = UserInfo {
                        id: Uuid::parse_str(&token_info.id).unwrap_or(Uuid::new_v4()),
                        username: token_info.username.to_string(),
                        email: None,
                        display_name: None,
                        groups: token_info.groups.clone(),
                        metadata: token_info.metadata.clone(),
                        created_at: token_info.created_at,
                        last_login: Some(chrono::Utc::now()),
                    };

                    Ok(AuthResult {
                        authenticated: true,
                        user_info: Some(user_info),
                        token: Some(token.to_string()),
                        mfa_required: false,
                        policies: token_info.policies.clone(),
                        lease_duration: token_info.lease_duration.map(|d| d as i64),
                        renewable: Some(token_info.renewable),
                        accessor: None,
                        metadata: HashMap::new(),
                        mfa_methods: vec![],
                    })
                } else {
                    Err(SecretonError::InvalidCredentials("Invalid token".to_string()))
                }
            }
            _ => Err(SecretonError::InvalidCredentials),
        }
    }

    async fn validate_token(&self, token: &str) -> AuthMethodResult<UserInfo> {
        if let Some(token_info) = self.get_token_info(token).await {
            if token_info.is_expired() {
                return Err(SecretonError::TokenExpired);
            }

            Ok(UserInfo {
                username: token_info.username,
                id: Uuid::parse_str(&token_info.id).unwrap_or(Uuid::new_v4()),
                groups: token_info.groups,
                metadata: token_info.metadata,
                email: None,
                display_name: None,
                created_at: token_info.created_at,
                last_login: Some(token_info.created_at),
            })
        } else {
            Err(SecretonError::InvalidToken)
        }
    }

    async fn revoke_token(&self, token: &str) -> AuthMethodResult<()> {
        self.remove_token(token).await;
        Ok(())
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

/// Token information
#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub username: String,
    pub id: String,
    pub groups: Vec<String>,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub lease_duration: Option<u64>,
    pub renewable: bool,
}

impl TokenInfo {
    pub fn new(
        username: String,
        id: String,
        groups: Vec<String>,
        policies: Vec<String>,
        metadata: HashMap<String, String>,
        lease_duration: Option<u64>,
        renewable: bool,
    ) -> Self {
        let created_at = chrono::Utc::now();
        let expires_at = lease_duration.map(|duration| created_at + chrono::Duration::seconds(duration as i64));

        Self {
            username,
            id,
            groups,
            policies,
            metadata,
            created_at,
            expires_at,
            lease_duration,
            renewable,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }
}