mod user;
mod refresh_token;
mod service;

pub use user::User;
pub use refresh_token::RefreshToken;
pub use service::{AuthService, TokenPair};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    core::error::AppError,
    server::AppState,
};
use crate::auth::mfa::MfaManager;

// API request/response types

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

// API Handlers

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let (user, tokens) = state
        .auth_service
        .authenticate(&payload.username, &payload.password)
        .await
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;

    Ok(Json(AuthResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
    }))
}

pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let tokens = state
        .auth_service
        .refresh_token(&payload.refresh_token)
        .await
        .map_err(|_| AppError::Unauthorized("Invalid refresh token".to_string()))?;

    Ok(Json(AuthResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
    }))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    state
        .auth_service
        .revoke_refresh_token(&payload.refresh_token)
        .await
        .map_err(|_| AppError::InternalServerError("Failed to revoke token".to_string()))?;

    Ok((StatusCode::NO_CONTENT, ()))
}

// Middleware for protected routes

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, AppError> {
    // Extract token from Authorization header
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized("Invalid authorization header format".to_string()));
    }

    let token = &auth_header[7..]; // Skip "Bearer "
    
    // Verify the token
    let claims = state
        .auth_service
        .verify_access_token(token)
        .map_err(|_| AppError::Unauthorized("Invalid or expired token".to_string()))?;

    // You can add additional checks here, like:
    // - Check if user exists and is active
    // - Check user permissions
    // - Log the access

    // Add user info to request extensions for use in handlers
    let mut request = request;
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

// Legacy code - to be removed after migration
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // username
    pub exp: i64,    // expiration time
    pub iat: i64,    // issued at
    pub mfa_verified: bool, // MFA verification status
    pub entity_alias: Option<String>, // untuk OIDC/LDAP/AppRole
}

pub struct AuthManager {
    jwt_secret: String,
    storage: Arc<dyn crate::storage::StorageBackend>,
    mfa_manager: Arc<MfaManager>,
}

impl AuthManager {
    pub fn new(jwt_secret: &str, storage: Arc<dyn crate::storage::StorageBackend>) -> Result<Self> {
        // Initialize MFA manager with max 5 attempts
        let mfa_manager = Arc::new(MfaManager::new(Arc::clone(&storage), 5));
        
        Ok(Self {
            jwt_secret: jwt_secret.to_string(),
            storage,
            mfa_manager,
        })
    }

    pub async fn authenticate(&self, username: &str, password: &str, mfa_code: Option<&str>) -> Result<String> {
        // Verify password with storage first
        if !self.storage.authenticate_user(username, password).await? {
            return Err(anyhow!("Invalid credentials"));
        }
        
        // Check if MFA is enabled for this user
        let mfa_enabled = self.storage.is_mfa_enabled(username).await
            .map_err(|e| {
                error!("Failed to check MFA status: {}", e);
                anyhow!("Authentication failed")
            })?;
            
        // If MFA is enabled, verify the MFA code
        if mfa_enabled {
            let mfa_code = mfa_code.ok_or_else(|| anyhow!("MFA code is required"))?;
            
            // Verify the MFA code using MFA manager
            let is_valid = self.mfa_manager.verify_totp(username, mfa_code).await
                .map_err(|e| {
                    error!("MFA verification failed: {}", e);
                    anyhow!("Invalid MFA code")
                })?;
                
            if !is_valid {
                return Err(anyhow!("Invalid MFA code"));
            }
            
            // Generate token with MFA verified flag
            let token = self.generate_token(username, true)?;
            info!("User {} authenticated successfully with MFA", username);
            return Ok(token);
        }
        
        // If MFA is not enabled, generate token without MFA verification
        let token = self.generate_token(username, false)?;
        info!("User {} authenticated successfully without MFA", username);
        Ok(token)
    }

    pub fn generate_token(&self, username: &str, mfa_verified: bool) -> Result<String> {
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        let claims = Claims {
            sub: username.to_string(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            mfa_verified,
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