//! Token renewal functionality

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::core::*;
use secreton_domain::SecretonError;

/// Token renewal service trait
#[async_trait]
pub trait TokenRenewalService: Send + Sync {
    /// Renew a token
    async fn renew_token(
        &self,
        request: TokenRenewalRequest,
    ) -> Result<TokenRenewalResponse, SecretonError>;

    /// Get renewal information for a token
    async fn get_renewal_info(&self, token_id: Uuid) -> Result<TokenRenewalInfo, SecretonError>;
}

/// Token renewal information
#[derive(Debug)]
pub struct TokenRenewalInfo {
    pub token_id: Uuid,
    pub renewable: bool,
    pub time_remaining: Option<Duration>,
    pub last_renewal: Option<DateTime<Utc>>,
    pub max_ttl: Option<Duration>,
}

/// In-memory token renewal service implementation
pub struct InMemoryTokenRenewalService {
    tokens: Arc<RwLock<HashMap<Uuid, Token>>>,
    default_increment: Duration,
    max_ttl: Option<Duration>,
}

impl InMemoryTokenRenewalService {
    pub fn new(
        tokens: Arc<RwLock<HashMap<Uuid, Token>>>,
        default_increment: Duration,
        max_ttl: Option<Duration>,
    ) -> Self {
        Self {
            tokens,
            default_increment,
            max_ttl,
        }
    }
}

#[async_trait]
impl TokenRenewalService for InMemoryTokenRenewalService {
    async fn renew_token(
        &self,
        request: TokenRenewalRequest,
    ) -> Result<TokenRenewalResponse, SecretonError> {
        let mut tokens = self.tokens.write().await;

        let token =
            tokens
                .get_mut(&request.token_id)
                .ok_or_else(|| SecretonError::TokenInvalid {
                    reason: request.token_id.to_string(),
                })?;

        // Check if token is valid
        if !token.is_valid() {
            return Err(SecretonError::TokenInvalid {
                reason: request.token_id.to_string(),
            });
        }

        // Renew the token
        let increment = request.increment.or(Some(self.default_increment));
        token.renew(increment, self.max_ttl)?;

        Ok(TokenRenewalResponse {
            token: token.clone(),
        })
    }

    async fn get_renewal_info(&self, token_id: Uuid) -> Result<TokenRenewalInfo, SecretonError> {
        let tokens = self.tokens.read().await;
        let token = tokens
            .get(&token_id)
            .ok_or_else(|| SecretonError::TokenInvalid {
                reason: token_id.to_string(),
            })?;

        let time_remaining = token
            .expiry_time
            .map(|expiry| expiry.signed_duration_since(Utc::now()));

        Ok(TokenRenewalInfo {
            token_id,
            renewable: token.renewable,
            time_remaining,
            last_renewal: token.last_renewal_time,
            max_ttl: token.explicit_max_ttl.or(self.max_ttl),
        })
    }
}
