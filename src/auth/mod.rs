use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use anyhow::Result;
use tracing::info;

use crate::storage::Storage;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // username
    pub exp: i64,    // expiration time
    pub iat: i64,    // issued at
    pub entity_alias: Option<String>, // untuk OIDC/LDAP/AppRole
}

pub struct AuthManager {
    jwt_secret: String,
    storage: std::sync::Arc<dyn crate::storage::StorageBackend>,
}

impl AuthManager {
    pub fn new(jwt_secret: &str, storage: std::sync::Arc<dyn crate::storage::StorageBackend>) -> Result<Self> {
        Ok(Self {
            jwt_secret: jwt_secret.to_string(),
            storage,
        })
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<String> {
        // Verifikasi password hash dengan storage
        if self.storage.authenticate_user(username, password).await? {
            let token = self.generate_token(username)?;
            let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();
            self.storage.insert_token(username, &token, Some(&expires_at)).await?;
            info!("User {} authenticated successfully", username);
            Ok(token)
        } else {
            Err(anyhow::anyhow!("Invalid credentials"))
        }
    }

    pub fn generate_token(&self, username: &str) -> Result<String> {
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        let claims = Claims {
            sub: username.to_string(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            entity_alias: None, // Default to None for now
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )?;

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }

    pub fn extract_token_from_header(auth_header: &str) -> Option<String> {
        if auth_header.starts_with("Bearer ") {
            Some(auth_header[7..].to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_authenticate() {
        let auth_manager = AuthManager::new("test_secret", std::sync::Arc::new(Storage::new("test.db").await.unwrap())).unwrap();
        
        // Test valid credentials
        let result = auth_manager.authenticate("admin", "admin").await;
        assert!(result.is_ok());
        
        // Test invalid credentials
        let result = auth_manager.authenticate("admin", "wrong").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_token_generation_and_verification() {
        let auth_manager = AuthManager::new("test_secret", std::sync::Arc::new(Storage::new("test.db").await.unwrap())).unwrap();
        
        let token = auth_manager.generate_token("test_user").unwrap();
        let claims = auth_manager.verify_token(&token).unwrap();
        
        assert_eq!(claims.sub, "test_user");
    }
} 