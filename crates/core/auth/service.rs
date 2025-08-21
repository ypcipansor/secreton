use std::sync::Arc;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use uuid::Uuid;
use anyhow::{Result, anyhow};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
    core::error::AppError,
    auth::{
        user::User,
        refresh_token::RefreshToken,
    },
};

#[derive(Debug, Clone)]
pub struct AuthService {
    jwt_secret: String,
    refresh_secret: String,
    access_token_ttl: i64, // in seconds
    refresh_token_ttl: i64, // in seconds
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,         // user ID
    pub exp: i64,          // expiration time
    pub iat: i64,          // issued at
    pub email: String,     // user email
    pub username: String,  // username
    pub roles: Vec<String>, // user roles
    pub scopes: Vec<String>,
}

impl AuthService {
    pub fn new(
        jwt_secret: &str,
        refresh_secret: &str,
        access_token_ttl: i64,
        refresh_token_ttl: i64,
    ) -> Self {
        Self {
            jwt_secret: jwt_secret.to_string(),
            refresh_secret: refresh_secret.to_string(),
            access_token_ttl,
            refresh_token_ttl,
        }
    }

    /// Authenticate a user with email/username and password
    pub async fn authenticate(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<(User, TokenPair)> {
        // TODO: Replace with actual user lookup from database
        // This is a mock implementation
        if identifier != "admin" || password != "admin" {
            return Err(anyhow!("Invalid credentials"));
        }

        let user = User::new(
            "admin".to_string(),
            "admin@example.com".to_string(),
            "admin", // In real app, this would be hashed
            true,
        )?;

        // Generate tokens
        let token_pair = self.generate_token_pair(&user, vec!["read", "write"])?;
        
        Ok((user, token_pair))
    }

    /// Generate a new access and refresh token pair
    pub fn generate_token_pair(
        &self,
        user: &User,
        scopes: Vec<&str>,
    ) -> Result<TokenPair> {
        let access_token = self.generate_access_token(user, &scopes)?;
        let refresh_token = self.generate_refresh_token(user, &scopes)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl,
        })
    }

    /// Generate a new access token
    pub fn generate_access_token(&self, user: &User, scopes: &[&str]) -> Result<String> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.access_token_ttl);

        let claims = Claims {
            sub: user.id,
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            email: user.email.clone(),
            username: user.username.clone(),
            roles: user.roles.iter().cloned().collect(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )
        .map_err(|e| anyhow!("Failed to generate access token: {}", e))?;

        Ok(token)
    }

    /// Generate a new refresh token
    pub fn generate_refresh_token(&self, user: &User, scopes: &[&str]) -> Result<String> {
        let refresh_token = RefreshToken::new(
            user.id,
            self.refresh_token_ttl,
            scopes.to_vec(),
            "brankas-adhyaksa",
            self.refresh_secret.as_bytes(),
        )?;

        // TODO: Store refresh token in database
        
        Ok(refresh_token.token)
    }

    /// Verify and decode an access token
    pub fn verify_access_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::default(),
        )
        .map_err(|e| anyhow!("Invalid token: {}", e))?;

        // Check if token is expired
        let now = Utc::now().timestamp();
        if token_data.claims.exp < now {
            return Err(anyhow!("Token has expired"));
        }

        Ok(token_data.claims)
    }

    /// Refresh an access token using a refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair> {
        // TODO: Verify refresh token from database
        // For now, we'll just validate the JWT structure
        
        // In a real implementation, we would:
        // 1. Verify the refresh token signature
        // 2. Check if it exists in the database and isn't revoked
        // 3. Get the associated user
        // 4. Generate a new token pair
        
        // This is a mock implementation
        if refresh_token.is_empty() {
            return Err(anyhow!("Invalid refresh token"));
        }

        // Mock user - in real app, get from database
        let user = User::new(
            "admin".to_string(),
            "admin@example.com".to_string(),
            "admin",
            true,
        )?;

        self.generate_token_pair(&user, vec!["read", "write"])
    }

    /// Invalidate a refresh token
    pub async fn revoke_refresh_token(&self, token: &str) -> Result<()> {
        // TODO: Implement token revocation in database
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_JWT_SECRET: &str = "test_jwt_secret_12345678901234567890123456789012";
    const TEST_REFRESH_SECRET: &str = "test_refresh_secret_12345678901234567890123456789012";

    fn create_test_service() -> AuthService {
        AuthService::new(
            TEST_JWT_SECRET,
            TEST_REFRESH_SECRET,
            300,   // 5 minutes
            86400, // 1 day
        )
    }

    #[tokio::test]
    async fn test_authenticate_success() {
        let service = create_test_service();
        let (user, tokens) = service.authenticate("admin", "admin").await.unwrap();
        
        assert_eq!(user.username, "admin");
        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.token_type, "Bearer");
    }

    #[tokio::test]
    async fn test_token_verification() {
        let service = create_test_service();
        let (user, tokens) = service.authenticate("admin", "admin").await.unwrap();
        
        let claims = service.verify_access_token(&tokens.access_token).unwrap();
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.username, "admin");
    }

    #[tokio::test]
    async fn test_token_refresh() {
        let service = create_test_service();
        let (_, tokens) = service.authenticate("admin", "admin").await.unwrap();
        
        let new_tokens = service.refresh_token(&tokens.refresh_token).await.unwrap();
        assert!(!new_tokens.access_token.is_empty());
        
        // Verify the new access token
        let claims = service.verify_access_token(&new_tokens.access_token).unwrap();
        assert_eq!(claims.username, "admin");
    }
}
