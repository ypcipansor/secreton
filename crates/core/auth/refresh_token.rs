use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,         // User ID
    pub jti: Uuid,         // Token ID
    pub exp: i64,          // Expiration time
    pub iat: i64,          // Issued at
    pub scope: String,     // Token scope
    pub client_id: String, // Client identifier
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
    pub scopes: HashSet<String>,
    pub client_id: String,
}

impl RefreshToken {
    pub fn new(
        user_id: Uuid,
        ttl_seconds: i64,
        scopes: Vec<&str>,
        client_id: &str,
        secret: &[u8],
    ) -> Result<Self> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds);
        let token_id = Uuid::new_v4();
        let token_claims = RefreshTokenClaims {
            sub: user_id,
            jti: token_id,
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            scope: scopes.join(" "),
            client_id: client_id.to_string(),
        };

        let token = encode(
            &Header::default(),
            &token_claims,
            &EncodingKey::from_secret(secret),
        )
        .map_err(|e| anyhow!("Failed to encode refresh token: {}", e))?;

        Ok(Self {
            id: token_id,
            user_id,
            token,
            expires_at,
            created_at: now,
            revoked: false,
            scopes: scopes.into_iter().map(String::from).collect(),
            client_id: client_id.to_string(),
        })
    }

    pub fn verify(&self, secret: &[u8]) -> Result<RefreshTokenClaims> {
        if self.revoked {
            return Err(anyhow!("Token has been revoked"));
        }

        if Utc::now() > self.expires_at {
            return Err(anyhow!("Token has expired"));
        }

        let token_data = decode::<RefreshTokenClaims>(
            &self.token,
            &DecodingKey::from_secret(secret),
            &Validation::default(),
        )
        .map_err(|e| anyhow!("Invalid token: {}", e))?;

        if token_data.claims.jti != self.id || token_data.claims.sub != self.user_id {
            return Err(anyhow!("Token validation failed"));
        }

        Ok(token_data.claims)
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn is_valid(&self) -> bool {
        !self.revoked && Utc::now() <= self.expires_at
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test_secret_key_for_testing_purposes";

    #[test]
    fn test_refresh_token_creation_and_verification() {
        let user_id = Uuid::new_v4();
        let scopes = vec!["read", "write"];
        let client_id = "test_client";

        let token = RefreshToken::new(
            user_id,
            3600, // 1 hour
            scopes.clone(),
            client_id,
            TEST_SECRET,
        )
        .unwrap();

        assert_eq!(token.user_id, user_id);
        assert!(!token.revoked);
        assert!(token.is_valid());
        assert!(token.has_scope("read"));
        assert!(token.has_scope("write"));
        assert!(!token.has_scope("admin"));

        // Verify the token
        let claims = token.verify(TEST_SECRET).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.client_id, client_id);
        assert_eq!(claims.scope, "read write");
    }

    #[test]
    fn test_token_revocation() {
        let mut token = RefreshToken::new(
            Uuid::new_v4(),
            3600,
            vec!["read"],
            "test_client",
            TEST_SECRET,
        )
        .unwrap();

        assert!(token.is_valid());

        token.revoke();

        assert!(!token.is_valid());
        assert!(token.verify(TEST_SECRET).is_err());
    }

    #[test]
    fn test_expired_token() {
        let token = RefreshToken::new(
            Uuid::new_v4(),
            -3600, // Expired 1 hour ago
            vec!["read"],
            "test_client",
            TEST_SECRET,
        )
        .unwrap();

        assert!(!token.is_valid());
        assert!(token.verify(TEST_SECRET).is_err());
    }
}
