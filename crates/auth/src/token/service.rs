//! Unified token service combining creation, renewal, and revocation

use async_trait::async_trait;
use chrono::{Duration, Utc};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::core::*;
use super::renewal::*;
use super::revocation::*;
use crate::service::AuthMethodResult;
use secreton_errors::SecretonError;

/// Token service trait
#[async_trait]
pub trait TokenService: Send + Sync {
    /// Create a new token
    async fn create_token(
        &self,
        request: TokenCreationRequest,
    ) -> AuthMethodResult<TokenCreationResponse>;

    /// Lookup a token by accessor
    async fn lookup_token(
        &self,
        request: TokenLookupRequest,
    ) -> AuthMethodResult<TokenLookupResponse>;

    /// Renew a token
    async fn renew_token(
        &self,
        request: TokenRenewalRequest,
    ) -> AuthMethodResult<TokenRenewalResponse>;

    /// Revoke a token
    async fn revoke_token(&self, request: TokenRevocationRequest) -> AuthMethodResult<()>;

    /// Revoke all tokens for an entity
    async fn revoke_entity_tokens(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// List tokens
    async fn list_tokens(&self, request: TokenListRequest) -> AuthMethodResult<Vec<Token>>;

    /// Clean up expired tokens
    async fn cleanup_expired(&self) -> AuthMethodResult<usize>;
}

/// Combined token service implementation
pub struct CombinedTokenService {
    tokens: Arc<RwLock<HashMap<Uuid, Token>>>,
    accessor_map: Arc<RwLock<HashMap<String, Uuid>>>,
    renewal_service: Arc<dyn TokenRenewalService>,
    revocation_service: Arc<dyn TokenRevocationService>,
    default_ttl: Duration,
    max_ttl: Option<Duration>,
}

impl CombinedTokenService {
    pub fn new(
        renewal_service: Arc<dyn TokenRenewalService>,
        revocation_service: Arc<dyn TokenRevocationService>,
        default_ttl: Duration,
        max_ttl: Option<Duration>,
    ) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            accessor_map: Arc::new(RwLock::new(HashMap::new())),
            renewal_service,
            revocation_service,
            default_ttl,
            max_ttl,
        }
    }

    fn generate_accessor() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        hex::encode(bytes)
    }

    fn generate_client_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        hex::encode(bytes)
    }

    /// Apply TTL constraints
    fn apply_ttl_constraints(
        &self,
        requested_ttl: Option<Duration>,
        explicit_max_ttl: Option<Duration>,
    ) -> Duration {
        let effective_max_ttl = explicit_max_ttl
            .or(self.max_ttl)
            .unwrap_or(self.default_ttl);
        requested_ttl
            .unwrap_or(self.default_ttl)
            .min(effective_max_ttl)
    }
}

#[async_trait]
impl TokenService for CombinedTokenService {
    async fn create_token(
        &self,
        request: TokenCreationRequest,
    ) -> AuthMethodResult<TokenCreationResponse> {
        let ttl = self.apply_ttl_constraints(request.ttl, request.explicit_max_ttl);
        let expiry_time = Some(Utc::now() + ttl);

        let token = Token {
            id: Uuid::new_v4(),
            accessor: Self::generate_accessor(),
            entity_id: request.entity_id,
            token_type: request.token_type,
            policies: request.policies,
            metadata: request.metadata,
            creation_time: Utc::now(),
            expiry_time,
            last_renewal_time: None,
            status: TokenStatus::Active,
            renewable: request.renewable,
            explicit_max_ttl: request.explicit_max_ttl,
            num_uses: request.num_uses,
            remaining_uses: request.num_uses,
        };

        let client_token = Self::generate_client_token();

        // Store the token
        let mut tokens = self.tokens.write().await;
        let mut accessor_map = self.accessor_map.write().await;

        tokens.insert(token.id, token.clone());
        accessor_map.insert(token.accessor.clone(), token.id);

        Ok(TokenCreationResponse {
            token,
            client_token,
        })
    }

    async fn lookup_token(
        &self,
        request: TokenLookupRequest,
    ) -> AuthMethodResult<TokenLookupResponse> {
        let accessor_map = self.accessor_map.read().await;
        let tokens = self.tokens.read().await;

        let token_id =
            accessor_map
                .get(&request.accessor)
                .ok_or_else(|| SecretonError::TokenInvalid {
                    reason: format!("Invalid accessor: {}", request.accessor),
                })?;

        let token = tokens
            .get(token_id)
            .ok_or_else(|| SecretonError::TokenInvalid {
                reason: format!("Token not found for accessor: {}", request.accessor),
            })?;

        if self.revocation_service.is_revoked(*token_id).await? {
            return Err(SecretonError::TokenRevoked);
        }

        Ok(TokenLookupResponse {
            token: token.clone(),
            renewable: token.can_renew(self.max_ttl),
            remaining_uses: token.remaining_uses,
        })
    }

    async fn renew_token(
        &self,
        request: TokenRenewalRequest,
    ) -> AuthMethodResult<TokenRenewalResponse> {
        if self.revocation_service.is_revoked(request.token_id).await? {
            return Err(SecretonError::TokenRevoked);
        }

        Ok(self.renewal_service.renew_token(request).await?)
    }

    async fn revoke_token(&self, request: TokenRevocationRequest) -> AuthMethodResult<()> {
        self.revocation_service.revoke_token(request).await?;
        Ok(())
    }

    async fn revoke_entity_tokens(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        self.revocation_service
            .revoke_entity_tokens(entity_id)
            .await?;
        Ok(())
    }

    async fn list_tokens(&self, request: TokenListRequest) -> AuthMethodResult<Vec<Token>> {
        let tokens = self.tokens.read().await;

        let filtered_tokens: Vec<Token> = tokens
            .values()
            .filter(|token| {
                // Filter by entity_id if specified
                if let Some(entity_id) = request.entity_id
                    && token.entity_id != Some(entity_id) {
                    return false;
                }

                // Filter by token_type if specified
                if let Some(token_type) = &request.token_type
                    && token.token_type != *token_type {
                    return false;
                }

                true
            })
            .cloned()
            .collect();

        Ok(filtered_tokens)
    }

    async fn cleanup_expired(&self) -> AuthMethodResult<usize> {
        let mut tokens = self.tokens.write().await;
        let mut accessor_map = self.accessor_map.write().await;

        let expired_ids: Vec<Uuid> = tokens
            .values()
            .filter(|token| token.is_expired())
            .map(|token| token.id)
            .collect();

        for token_id in &expired_ids {
            if let Some(token) = tokens.get(token_id) {
                accessor_map.remove(&token.accessor);
            }
            tokens.remove(token_id);
        }

        Ok(expired_ids.len())
    }
}
