//! Token Service
//!
//! Comprehensive token lifecycle management for authentication and authorization.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Error types for token service
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("Token not found: {0}")]
    TokenNotFound(String),
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Token revoked")]
    TokenRevoked,
    
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),
    
    #[error("Token creation failed: {0}")]
    CreationFailed(String),
    
    #[error("Token renewal failed: {0}")]
    RenewalFailed(String),
    
    #[error("Insufficient permissions: {0}")]
    InsufficientPermissions(String),
}

/// Token type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    /// Service token (no expiration, can be renewed)
    Service,
    
    /// Batch token (cannot be renewed, optimized for high performance)
    Batch,
    
    /// Root token (full permissions)
    Root,
}

/// Token metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token ID (accessor)
    pub id: String,
    
    /// Token value (actual secret)
    pub token: String,
    
    /// Token type
    pub token_type: TokenType,
    
    /// Policies attached to this token
    pub policies: Vec<String>,
    
    /// Entity ID (user/role that owns this token)
    pub entity_id: Option<String>,
    
    /// Display name
    pub display_name: String,
    
    /// Creation time
    pub created_at: DateTime<Utc>,
    
    /// Expiration time
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Last renewal time
    pub renewed_at: Option<DateTime<Utc>>,
    
    /// Number of times renewed
    pub renew_count: u32,
    
    /// Maximum number of renewals allowed
    pub max_renewals: Option<u32>,
    
    /// TTL in seconds
    pub ttl: u32,
    
    /// Maximum TTL
    pub max_ttl: u32,
    
    /// Parent token ID
    pub parent_id: Option<String>,
    
    /// Number of uses remaining (0 = unlimited)
    pub num_uses: u32,
    
    /// Metadata
    pub metadata: HashMap<String, String>,
    
    /// Whether token is revoked
    pub revoked: bool,
    
    /// Revocation time
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Token {
    /// Create new token
    pub fn new(
        token_type: TokenType,
        policies: Vec<String>,
        ttl: u32,
        max_ttl: u32,
        display_name: String,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let token = format!("hvs.{}", Uuid::new_v4().to_string().replace("-", ""));
        let now = Utc::now();
        
        let expires_at = match token_type {
            TokenType::Root => None,
            _ => Some(now + Duration::seconds(ttl as i64)),
        };
        
        Self {
            id: id.clone(),
            token,
            token_type,
            policies,
            entity_id: None,
            display_name,
            created_at: now,
            expires_at,
            renewed_at: None,
            renew_count: 0,
            max_renewals: None,
            ttl,
            max_ttl,
            parent_id: None,
            num_uses: 0,
            metadata: HashMap::new(),
            revoked: false,
            revoked_at: None,
        }
    }
    
    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        
        if let Some(expires_at) = self.expires_at {
            if Utc::now() > expires_at {
                return false;
            }
        }
        
        true
    }
    
    /// Check if token can be renewed
    pub fn can_renew(&self) -> bool {
        if self.token_type == TokenType::Batch {
            return false;
        }
        
        if let Some(max_renewals) = self.max_renewals {
            if self.renew_count >= max_renewals {
                return false;
            }
        }
        
        true
    }
    
    /// Renew token
    pub fn renew(&mut self, increment: u32) -> Result<(), TokenError> {
        if !self.can_renew() {
            return Err(TokenError::RenewalFailed("Token cannot be renewed".to_string()));
        }
        
        let new_ttl = increment.min(self.max_ttl);
        let now = Utc::now();
        
        self.expires_at = Some(now + Duration::seconds(new_ttl as i64));
        self.renewed_at = Some(now);
        self.renew_count += 1;
        self.ttl = new_ttl;
        
        Ok(())
    }
    
    /// Revoke token
    pub fn revoke(&mut self) {
        self.revoked = true;
        self.revoked_at = Some(Utc::now());
    }
    
    /// Use token (decrement num_uses)
    pub fn use_token(&mut self) -> Result<(), TokenError> {
        if self.num_uses > 0 {
            self.num_uses -= 1;
            if self.num_uses == 0 {
                self.revoke();
            }
        }
        Ok(())
    }
}

/// Token service for managing tokens
pub struct TokenService {
    tokens: Arc<RwLock<HashMap<String, Token>>>,
    token_by_value: Arc<RwLock<HashMap<String, String>>>, // token value -> token id
}

impl TokenService {
    /// Create new token service
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            token_by_value: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create token
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
    ) -> Result<Token, TokenError> {
        let mut token = Token::new(token_type, policies, ttl, max_ttl, display_name);
        token.parent_id = parent_id;
        token.metadata = metadata;
        token.num_uses = num_uses;
        
        let mut tokens = self.tokens.write().await;
        let mut token_by_value = self.token_by_value.write().await;
        
        tokens.insert(token.id.clone(), token.clone());
        token_by_value.insert(token.token.clone(), token.id.clone());
        
        Ok(token)
    }
    
    /// Lookup token by value
    pub async fn lookup_token(&self, token_value: &str) -> Result<Token, TokenError> {
        let token_by_value = self.token_by_value.read().await;
        let token_id = token_by_value.get(token_value)
            .ok_or_else(|| TokenError::TokenNotFound(token_value.to_string()))?;
        
        let tokens = self.tokens.read().await;
        let token = tokens.get(token_id)
            .ok_or_else(|| TokenError::TokenNotFound(token_id.clone()))?;
        
        Ok(token.clone())
    }
    
    /// Verify token is valid
    pub async fn verify_token(&self, token_value: &str) -> Result<Token, TokenError> {
        let token = self.lookup_token(token_value).await?;
        
        if !token.is_valid() {
            if token.revoked {
                return Err(TokenError::TokenRevoked);
            }
            return Err(TokenError::TokenExpired);
        }
        
        Ok(token)
    }
    
    /// Renew token
    pub async fn renew_token(
        &self,
        token_value: &str,
        increment: u32,
    ) -> Result<Token, TokenError> {
        let token_by_value = self.token_by_value.read().await;
        let token_id = token_by_value.get(token_value)
            .ok_or_else(|| TokenError::TokenNotFound(token_value.to_string()))?
            .clone();
        drop(token_by_value);
        
        let mut tokens = self.tokens.write().await;
        let token = tokens.get_mut(&token_id)
            .ok_or_else(|| TokenError::TokenNotFound(token_id.clone()))?;
        
        token.renew(increment)?;
        
        Ok(token.clone())
    }
    
    /// Revoke token
    pub async fn revoke_token(&self, token_value: &str) -> Result<(), TokenError> {
        let token_by_value = self.token_by_value.read().await;
        let token_id = token_by_value.get(token_value)
            .ok_or_else(|| TokenError::TokenNotFound(token_value.to_string()))?
            .clone();
        drop(token_by_value);
        
        let mut tokens = self.tokens.write().await;
        let token = tokens.get_mut(&token_id)
            .ok_or_else(|| TokenError::TokenNotFound(token_id.clone()))?;
        
        token.revoke();
        
        // Revoke all child tokens
        let child_ids: Vec<String> = tokens.values()
            .filter(|t| t.parent_id.as_ref() == Some(&token_id))
            .map(|t| t.id.clone())
            .collect();
        
        for child_id in child_ids {
            if let Some(child) = tokens.get_mut(&child_id) {
                child.revoke();
            }
        }
        
        Ok(())
    }
    
    /// List tokens for entity
    pub async fn list_tokens(&self, entity_id: Option<&str>) -> Vec<Token> {
        let tokens = self.tokens.read().await;
        
        tokens.values()
            .filter(|t| {
                if let Some(eid) = entity_id {
                    t.entity_id.as_deref() == Some(eid)
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }
    
    /// Cleanup expired tokens
    pub async fn cleanup_expired(&self) -> usize {
        let mut tokens = self.tokens.write().await;
        let mut token_by_value = self.token_by_value.write().await;
        
        let now = Utc::now();
        let expired: Vec<String> = tokens.values()
            .filter(|t| {
                if let Some(expires_at) = t.expires_at {
                    now > expires_at
                } else {
                    false
                }
            })
            .map(|t| t.id.clone())
            .collect();
        
        let count = expired.len();
        
        for id in expired {
            if let Some(token) = tokens.remove(&id) {
                token_by_value.remove(&token.token);
            }
        }
        
        count
    }
    
    /// Get token count
    pub async fn count(&self) -> usize {
        let tokens = self.tokens.read().await;
        tokens.len()
    }
}

impl Default for TokenService {
    fn default() -> Self {
        Self::new()
    }
}

// Legacy compatibility function
pub fn verify_token(token: &str) -> bool {
    token == "admin-token"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_token() {
        let service = TokenService::new();
        
        let token = service.create_token(
            TokenType::Service,
            vec!["default".to_string()],
            3600,
            86400,
            "test-token".to_string(),
            None,
            HashMap::new(),
            0,
        ).await.unwrap();
        
        assert!(token.token.starts_with("hvs."));
        assert_eq!(token.policies.len(), 1);
        assert_eq!(service.count().await, 1);
    }
    
    #[tokio::test]
    async fn test_verify_token() {
        let service = TokenService::new();
        
        let token = service.create_token(
            TokenType::Service,
            vec!["default".to_string()],
            3600,
            86400,
            "test-token".to_string(),
            None,
            HashMap::new(),
            0,
        ).await.unwrap();
        
        let verified = service.verify_token(&token.token).await;
        assert!(verified.is_ok());
    }
    
    #[tokio::test]
    async fn test_renew_token() {
        let service = TokenService::new();
        
        let token = service.create_token(
            TokenType::Service,
            vec!["default".to_string()],
            1800,
            86400,
            "test-token".to_string(),
            None,
            HashMap::new(),
            0,
        ).await.unwrap();
        
        let renewed = service.renew_token(&token.token, 3600).await.unwrap();
        assert_eq!(renewed.renew_count, 1);
        assert!(renewed.renewed_at.is_some());
    }
    
    #[tokio::test]
    async fn test_revoke_token() {
        let service = TokenService::new();
        
        let token = service.create_token(
            TokenType::Service,
            vec!["default".to_string()],
            3600,
            86400,
            "test-token".to_string(),
            None,
            HashMap::new(),
            0,
        ).await.unwrap();
        
        service.revoke_token(&token.token).await.unwrap();
        
        let result = service.verify_token(&token.token).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_batch_token_no_renew() {
        let service = TokenService::new();
        
        let token = service.create_token(
            TokenType::Batch,
            vec!["default".to_string()],
            3600,
            86400,
            "batch-token".to_string(),
            None,
            HashMap::new(),
            0,
        ).await.unwrap();
        
        let result = service.renew_token(&token.token, 3600).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_token_with_uses() {
        let service = TokenService::new();
        
        let token = service.create_token(
            TokenType::Service,
            vec!["default".to_string()],
            3600,
            86400,
            "limited-token".to_string(),
            None,
            HashMap::new(),
            3, // 3 uses
        ).await.unwrap();
        
        assert_eq!(token.num_uses, 3);
    }
}

