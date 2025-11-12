//! Token revocation functionality

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::token::*;
use secreton_errors::SecretonError;

/// Token revocation service trait
#[async_trait]
pub trait TokenRevocationService: Send + Sync {
    /// Revoke a specific token
    async fn revoke_token(&self, request: TokenRevocationRequest) -> Result<(), SecretonError>;

    /// Revoke all tokens for an entity
    async fn revoke_entity_tokens(&self, entity_id: Uuid) -> Result<(), SecretonError>;

    /// Revoke tokens by accessor prefix
    async fn revoke_by_prefix(&self, prefix: String) -> Result<(), SecretonError>;

    /// Check if a token is revoked
    async fn is_revoked(&self, token_id: Uuid) -> Result<bool, SecretonError>;

    /// Get revocation information
    async fn get_revocation_info(
        &self,
        token_id: Uuid,
    ) -> Result<Option<TokenRevocationInfo>, SecretonError>;
}

/// Token revocation information
#[derive(Debug)]
pub struct TokenRevocationInfo {
    pub token_id: Uuid,
    pub revoked_at: DateTime<Utc>,
    pub reason: RevocationReason,
}

/// Revocation reason
#[derive(Debug, Clone)]
pub enum RevocationReason {
    Explicit,
    EntityRevoked,
    PrefixRevoked,
    Expired,
    MaxUsesReached,
}

/// Revocation registry entry
#[derive(Debug)]
struct RevocationEntry {
    revoked_at: DateTime<Utc>,
    reason: RevocationReason,
}

/// In-memory token revocation service implementation
pub struct InMemoryTokenRevocationService {
    tokens: Arc<RwLock<HashMap<Uuid, Token>>>,
    revocations: RwLock<HashMap<Uuid, RevocationEntry>>,
    entity_revocations: RwLock<HashMap<Uuid, DateTime<Utc>>>,
    prefix_revocations: RwLock<HashSet<String>>,
}

impl InMemoryTokenRevocationService {
    pub fn new(tokens: Arc<RwLock<HashMap<Uuid, Token>>>) -> Self {
        Self {
            tokens,
            revocations: RwLock::new(HashMap::new()),
            entity_revocations: RwLock::new(HashMap::new()),
            prefix_revocations: RwLock::new(HashSet::new()),
        }
    }

    /// Revoke a token in the token store
    async fn revoke_token_in_store(
        &self,
        token_id: Uuid,
        reason: RevocationReason,
    ) -> Result<(), SecretonError> {
        let mut tokens = self.tokens.write().await;

        if let Some(token) = tokens.get_mut(&token_id) {
            token.revoke();

            // Record the revocation
            let revocation_entry = RevocationEntry {
                revoked_at: Utc::now(),
                reason,
            };

            let mut revocations = self.revocations.write().await;
            revocations.insert(token_id, revocation_entry);
        }

        Ok(())
    }
}

#[async_trait]
impl TokenRevocationService for InMemoryTokenRevocationService {
    async fn revoke_token(&self, request: TokenRevocationRequest) -> Result<(), SecretonError> {
        self.revoke_token_in_store(request.token_id, RevocationReason::Explicit)
            .await
    }

    async fn revoke_entity_tokens(&self, entity_id: Uuid) -> Result<(), SecretonError> {
        // Record entity revocation
        let now = Utc::now();
        let mut entity_revocations = self.entity_revocations.write().await;
        entity_revocations.insert(entity_id, now);

        // Revoke all tokens for this entity
        let tokens = self.tokens.read().await;
        let entity_token_ids: Vec<Uuid> = tokens
            .values()
            .filter(|token| token.entity_id == Some(entity_id))
            .map(|token| token.id)
            .collect();

        for token_id in entity_token_ids {
            self.revoke_token_in_store(token_id, RevocationReason::EntityRevoked)
                .await?;
        }

        Ok(())
    }

    async fn revoke_by_prefix(&self, prefix: String) -> Result<(), SecretonError> {
        // Record prefix revocation
        let mut prefix_revocations = self.prefix_revocations.write().await;
        prefix_revocations.insert(prefix.clone());

        // Revoke all tokens with this prefix
        let tokens = self.tokens.read().await;
        let prefix_token_ids: Vec<Uuid> = tokens
            .values()
            .filter(|token| token.accessor.starts_with(&prefix))
            .map(|token| token.id)
            .collect();

        for token_id in prefix_token_ids {
            self.revoke_token_in_store(token_id, RevocationReason::PrefixRevoked)
                .await?;
        }

        Ok(())
    }

    async fn is_revoked(&self, token_id: Uuid) -> Result<bool, SecretonError> {
        let revocations = self.revocations.read().await;
        Ok(revocations.contains_key(&token_id))
    }

    async fn get_revocation_info(
        &self,
        token_id: Uuid,
    ) -> Result<Option<TokenRevocationInfo>, SecretonError> {
        let revocations = self.revocations.read().await;

        if let Some(entry) = revocations.get(&token_id) {
            Ok(Some(TokenRevocationInfo {
                token_id,
                revoked_at: entry.revoked_at,
                reason: entry.reason.clone(),
            }))
        } else {
            Ok(None)
        }
    }
}
