//! Token data structures and types

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::*;

/// Token types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Service,
    Batch,
    Default,
}

/// Token status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenStatus {
    Active,
    Revoked,
    Expired,
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: Uuid,
    pub accessor: String,
    pub entity_id: Option<Uuid>,
    pub token_type: TokenType,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub creation_time: DateTime<Utc>,
    pub expiry_time: Option<DateTime<Utc>>,
    pub last_renewal_time: Option<DateTime<Utc>>,
    pub status: TokenStatus,
    pub renewable: bool,
    pub explicit_max_ttl: Option<Duration>,
    pub num_uses: Option<u32>,
    pub remaining_uses: Option<u32>,
}

/// Token creation request
#[derive(Debug, Deserialize)]
pub struct TokenCreationRequest {
    pub entity_id: Option<Uuid>,
    pub token_type: TokenType,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub ttl: Option<Duration>,
    pub renewable: bool,
    pub explicit_max_ttl: Option<Duration>,
    pub num_uses: Option<u32>,
}

/// Token renewal request
#[derive(Debug, Deserialize)]
pub struct TokenRenewalRequest {
    pub token_id: Uuid,
    pub increment: Option<Duration>,
}

/// Token revocation request
#[derive(Debug, Deserialize)]
pub struct TokenRevocationRequest {
    pub token_id: Uuid,
}

/// Token lookup request
#[derive(Debug, Deserialize)]
pub struct TokenLookupRequest {
    pub accessor: String,
}

/// Token lookup response
#[derive(Debug, Serialize)]
pub struct TokenLookupResponse {
    pub token: Token,
    pub renewable: bool,
    pub remaining_uses: Option<u32>,
}

/// Token list request
#[derive(Debug, Deserialize)]
pub struct TokenListRequest {
    pub entity_id: Option<Uuid>,
    pub token_type: Option<TokenType>,
}

/// Token creation response
#[derive(Debug, Serialize)]
pub struct TokenCreationResponse {
    pub token: Token,
    pub client_token: String,
}

/// Token renewal response
#[derive(Debug, Serialize)]
pub struct TokenRenewalResponse {
    pub token: Token,
}

impl Token {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry_time {
            Utc::now() > expiry
        } else {
            false
        }
    }

    /// Check if the token is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        self.status == TokenStatus::Active && !self.is_expired()
    }

    /// Check if the token can be renewed
    pub fn can_renew(&self, max_ttl: Option<Duration>) -> bool {
        if !self.renewable || self.status != TokenStatus::Active {
            return false;
        }

        // Check if renewing would exceed max TTL
        if let Some(max_ttl) = max_ttl {
            let current_age = Utc::now().signed_duration_since(self.creation_time);
            if current_age + max_ttl < Duration::zero() {
                return false;
            }
        }

        true
    }

    /// Consume a use of the token
    pub fn consume_use(&mut self) -> Result<(), AuthMethodError> {
        if let Some(remaining) = self.remaining_uses.as_mut() {
            if *remaining == 0 {
                return Err(AuthMethodError::InvalidToken);
            }
            *remaining -= 1;
        }
        Ok(())
    }

    /// Revoke the token
    pub fn revoke(&mut self) {
        self.status = TokenStatus::Revoked;
    }

    /// Renew the token
    pub fn renew(
        &mut self,
        increment: Option<Duration>,
        max_ttl: Option<Duration>,
    ) -> Result<(), AuthMethodError> {
        if !self.can_renew(max_ttl) {
            return Err(AuthMethodError::InvalidToken);
        }

        let now = Utc::now();

        if let Some(increment) = increment {
            self.expiry_time = Some(now + increment);
        } else if let Some(current_expiry) = self.expiry_time {
            // Default renewal is to extend to current expiry + default increment
            // For simplicity, we'll extend by the same duration
            let current_duration = current_expiry.signed_duration_since(self.creation_time);
            self.expiry_time = Some(now + current_duration);
        }

        // Apply max TTL constraint
        if let Some(max_ttl) = max_ttl {
            let max_expiry = self.creation_time + max_ttl;
            if let Some(current_expiry) = self.expiry_time {
                if current_expiry > max_expiry {
                    self.expiry_time = Some(max_expiry);
                }
            }
        }

        self.last_renewal_time = Some(now);
        Ok(())
    }
}
