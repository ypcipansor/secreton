//! JWT token management module
//!
//! This module provides JWT-based token creation, validation, and management
//! functionality that was previously in the separate token crate.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// JWT token management errors
#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token not found")]
    TokenNotFound,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Token type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    /// Access token for API operations
    Access,

    /// Refresh token for obtaining new access tokens
    Refresh,

    /// Service token (long-lived)
    Service,

    /// Batch token (high-performance, non-renewable)
    Batch,
}

/// Unified JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,

    /// Username
    pub username: String,

    /// Email address
    pub email: Option<String>,

    /// User roles
    pub roles: Vec<String>,

    /// Associated policies
    pub policies: Vec<String>,

    /// MFA required flag
    #[serde(default)]
    pub mfa_required: bool,

    /// Issued at timestamp
    pub iat: usize,

    /// Expiration timestamp
    pub exp: usize,

    /// Token issuer
    pub iss: String,

    /// Token audience
    pub aud: String,

    /// Token ID (unique identifier)
    pub jti: String,
}

/// Access token specific claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    /// Base claims
    #[serde(flatten)]
    pub claims: Claims,

    /// Token type (should be "access")
    pub token_type: String,
}

/// Refresh token specific claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenClaims {
    /// User ID
    pub sub: String,

    /// Username
    pub username: String,

    /// Issued at timestamp
    pub iat: usize,

    /// Expiration timestamp
    pub exp: usize,

    /// Token ID
    pub jti: String,
}

/// Token configuration
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// JWT secret for signing
    pub jwt_secret: String,

    /// JWT secret for refresh tokens
    pub jwt_refresh_secret: String,

    /// Access token duration
    pub access_token_duration: Duration,

    /// Refresh token duration
    pub refresh_token_duration: Duration,

    /// Token issuer
    pub issuer: String,

    /// Token audience
    pub audience: String,
}

/// Complete token pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Access token
    pub access_token: String,

    /// Refresh token
    pub refresh_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Access token expiration time in seconds
    pub expires_in: u64,

    /// Token metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            jwt_secret: std::env::var("SECRETON_JWT_SECRET").unwrap_or_else(|_| {
                let secret = Uuid::new_v4().to_string();
                eprintln!("NOTICE: SECRETON_JWT_SECRET not set. Generated a random secret. Tokens will be invalid after restart.");
                secret
            }),
            jwt_refresh_secret: std::env::var("SECRETON_JWT_REFRESH_SECRET").unwrap_or_else(|_| {
                let secret = Uuid::new_v4().to_string();
                eprintln!("NOTICE: SECRETON_JWT_REFRESH_SECRET not set. Generated a random secret. Tokens will be invalid after restart.");
                secret
            }),
            access_token_duration: Duration::hours(1),
            refresh_token_duration: Duration::days(7),
            issuer: "secreton".to_string(),
            audience: "secreton-api".to_string(),
        }
    }
}

/// JWT token service for unified token operations
#[derive(Clone)]
pub struct JwtTokenService {
    config: TokenConfig,
}

impl JwtTokenService {
    /// Create new JWT token service
    pub fn new(config: TokenConfig) -> Self {
        Self { config }
    }

    /// Create access token
    pub fn create_access_token(
        &self,
        user_id: &str,
        username: &str,
        email: Option<&str>,
        roles: &[String],
        policies: &[String],
        mfa_required: bool,
        jti: Option<String>,
    ) -> Result<String, JwtError> {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let exp = (now + self.config.access_token_duration).timestamp() as usize;

        let claims = AccessTokenClaims {
            claims: Claims {
                sub: user_id.to_string(),
                username: username.to_string(),
                email: email.map(|s| s.to_string()),
                roles: roles.to_vec(),
                policies: policies.to_vec(),
                mfa_required,
                iat,
                exp,
                iss: self.config.issuer.clone(),
                aud: self.config.audience.clone(),
                jti: jti.unwrap_or_else(|| Uuid::new_v4().to_string()),
            },
            token_type: "access".to_string(),
        };

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let encoding_key =
            jsonwebtoken::EncodingKey::from_secret(self.config.jwt_secret.as_bytes());

        jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(JwtError::JwtError)
    }

    /// Create refresh token
    pub fn create_refresh_token(&self, user_id: &str, username: &str) -> Result<String, JwtError> {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let exp = (now + self.config.refresh_token_duration).timestamp() as usize;

        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            username: username.to_string(),
            iat,
            exp,
            jti: Uuid::new_v4().to_string(),
        };

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let encoding_key =
            jsonwebtoken::EncodingKey::from_secret(self.config.jwt_refresh_secret.as_bytes());

        jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(JwtError::JwtError)
    }

    /// Create token pair (access + refresh)
    pub fn create_token_pair(
        &self,
        user_id: &str,
        username: &str,
        email: Option<&str>,
        roles: &[String],
        policies: &[String],
        mfa_required: bool,
        jti: Option<String>,
    ) -> Result<TokenPair, JwtError> {
        let access_token =
            self.create_access_token(user_id, username, email, roles, policies, mfa_required, jti)?;
        let refresh_token = self.create_refresh_token(user_id, username)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_duration.num_seconds() as u64,
            metadata: std::collections::HashMap::new(),
        })
    }

    /// Validate access token and return claims
    pub fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims, JwtError> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[&self.config.issuer]);
        let decoding_key =
            jsonwebtoken::DecodingKey::from_secret(self.config.jwt_secret.as_bytes());

        let token_data =
            jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
                .map_err(JwtError::JwtError)?;

        // Check expiration
        let now = Utc::now().timestamp() as usize;
        if token_data.claims.claims.exp < now {
            return Err(JwtError::TokenExpired);
        }

        Ok(token_data.claims)
    }

    /// Validate refresh token and return claims
    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims, JwtError> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        // Refresh tokens don't always carry audience claims in standard implementations unless configured,
        // but it's good practice. Assuming standard claims.
        // If refresh token doesn't have aud/iss, this might fail.
        // However, create_refresh_token doesn't seem to add iss/aud in current impl.
        // Let's check create_refresh_token.
        // It creates RefreshTokenClaims which has sub, username, iat, exp, jti. NO iss/aud.
        // So we cannot validate iss/aud here unless we add them to creation.

        let decoding_key =
            jsonwebtoken::DecodingKey::from_secret(self.config.jwt_refresh_secret.as_bytes());

        let token_data =
            jsonwebtoken::decode::<RefreshTokenClaims>(token, &decoding_key, &validation)
                .map_err(JwtError::JwtError)?;

        // Check expiration
        let now = Utc::now().timestamp() as usize;
        if token_data.claims.exp < now {
            return Err(JwtError::TokenExpired);
        }

        Ok(token_data.claims)
    }

    /// Refresh access token using refresh token
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        jti: Option<String>,
    ) -> Result<TokenPair, JwtError> {
        let refresh_claims = self.validate_refresh_token(refresh_token)?;

        // Create new token pair with same user info
        self.create_token_pair(
            &refresh_claims.sub,
            &refresh_claims.username,
            None,  // Email not stored in refresh token
            &[],   // Roles not stored in refresh token (should be fetched from user data)
            &[],   // Policies not stored in refresh token (should be fetched from user data)
            false, // MFA status should be checked separately
            jti,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_config_random_secrets() {
        // Ensure environment variables are not set for this test
        // Note: tests run in parallel, so modifying env vars might affect other tests
        // But since we only care about the default case here, we can try to rely on them not being set
        // or temporarily unset them if we can serialize tests.
        // Ideally we shouldn't modify global env in tests.
        // However, TokenConfig::default() reads env vars directly.
        // Assuming they are not set in the build environment.

        // We will only run assertions if the env vars are NOT set.
        if std::env::var("SECRETON_JWT_SECRET").is_err() {
            let config1 = TokenConfig::default();
            let config2 = TokenConfig::default();

            // Check it's not the old default
            assert_ne!(config1.jwt_secret, "default-secret-change-in-production");
            assert_ne!(
                config1.jwt_refresh_secret,
                "default-refresh-secret-change-in-production"
            );

            // Check randomness (highly unlikely to match)
            assert_ne!(config1.jwt_secret, config2.jwt_secret);
            assert_ne!(config1.jwt_refresh_secret, config2.jwt_refresh_secret);

            // Check length (UUID is 36 chars)
            assert_eq!(config1.jwt_secret.len(), 36);
            assert_eq!(config1.jwt_refresh_secret.len(), 36);
        }
    }
}
