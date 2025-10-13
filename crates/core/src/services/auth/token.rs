//! Token Authentication Method
//!
//! Direct token-based authentication using Vault tokens.
//! Wraps the TokenService for authentication purposes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use crate::services::token::{TokenService, TokenType, TokenError, Token};

/// Token auth errors
#[derive(Debug, thiserror::Error)]
pub enum TokenAuthError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Token error: {0}")]
    TokenError(#[from] TokenError),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Token authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAuthRequest {
    /// Token value
    pub token: String,
}

/// Token authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAuthResponse {
    /// Token metadata
    pub token: Token,
    
    /// Authenticated at
    pub authenticated_at: DateTime<Utc>,
    
    /// Client IP (if available)
    pub client_ip: Option<String>,
}

/// Token authentication service
pub struct TokenAuthService {
    token_service: Arc<TokenService>,
}

impl TokenAuthService {
    /// Create new token auth service
    pub fn new(token_service: Arc<TokenService>) -> Self {
        Self { token_service }
    }
    
    /// Authenticate using token
    pub async fn authenticate(
        &self,
        request: TokenAuthRequest,
        client_ip: Option<String>,
    ) -> Result<TokenAuthResponse, TokenAuthError> {
        // Verify token is valid
        let token = self.token_service.verify_token(&request.token).await?;
        
        // Check token is not expired or revoked (already done in verify_token)
        // Additional checks can be added here
        
        Ok(TokenAuthResponse {
            token,
            authenticated_at: Utc::now(),
            client_ip,
        })
    }
    
    /// Create a new token
    pub async fn create_token(
        &self,
        token_type: TokenType,
        policies: Vec<String>,
        ttl: u32,
        max_ttl: u32,
        display_name: String,
        parent_id: Option<String>,
        metadata: HashMap<String, String>,
        num_uses: u32,
    ) -> Result<Token, TokenAuthError> {
        let token = self.token_service
            .create_token(
                token_type,
                policies,
                ttl,
                max_ttl,
                display_name,
                parent_id,
                metadata,
                num_uses,
            )
            .await?;
        
        Ok(token)
    }
    
    /// Renew token
    pub async fn renew_token(
        &self,
        token_value: &str,
        increment: u32,
    ) -> Result<Token, TokenAuthError> {
        let token = self.token_service.renew_token(token_value, increment).await?;
        Ok(token)
    }
    
    /// Revoke token
    pub async fn revoke_token(&self, token_value: &str) -> Result<(), TokenAuthError> {
        self.token_service.revoke_token(token_value).await?;
        Ok(())
    }
    
    /// Lookup token
    pub async fn lookup_token(&self, token_value: &str) -> Result<Token, TokenAuthError> {
        let token = self.token_service.lookup_token(token_value).await?;
        Ok(token)
    }
}

impl Default for TokenAuthService {
    fn default() -> Self {
        Self::new(Arc::new(TokenService::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_authentication() {
        let service = TokenAuthService::default();
        
        // Create a token
        let token = service
            .create_token(
                TokenType::Service,
                vec!["default".to_string()],
                3600,
                86400,
                "test-token".to_string(),
                None,
                HashMap::new(),
                0,
            )
            .await
            .unwrap();
        
        // Authenticate with the token
        let auth_request = TokenAuthRequest {
            token: token.token.clone(),
        };
        
        let response = service
            .authenticate(auth_request, Some("127.0.0.1".to_string()))
            .await
            .unwrap();
        
        assert_eq!(response.token.id, token.id);
        assert_eq!(response.client_ip, Some("127.0.0.1".to_string()));
    }
    
    #[tokio::test]
    async fn test_token_renewal() {
        let service = TokenAuthService::default();
        
        let token = service
            .create_token(
                TokenType::Service,
                vec!["default".to_string()],
                3600,
                86400,
                "test-token".to_string(),
                None,
                HashMap::new(),
                0,
            )
            .await
            .unwrap();
        
        let renewed = service.renew_token(&token.token, 7200).await.unwrap();
        assert_eq!(renewed.renew_count, 1);
    }
}
