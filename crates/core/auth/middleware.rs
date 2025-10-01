use axum::{
    http::Request,
    middleware::Next,
    response::Response,
    extract::State,
    http::StatusCode,
    body::Bytes,
    Json,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use crate::storage::StorageBackend;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub exp: usize,         // Expiration time
    pub iat: usize,        // Issued at
    pub mfa_verified: bool, // Whether MFA has been verified
    pub roles: Vec<String>, // User roles
}

#[derive(Clone)]
pub struct AuthState<S: StorageBackend> {
    pub storage: Arc<S>,
    pub jwt_secret: String,
}

pub async fn auth_middleware<B, S: StorageBackend>(
    State(state): State<Arc<AuthState<S>>>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    // Skip auth for public routes - ONLY login/register endpoints
    let path = req.uri().path();
    if path.starts_with("/api/v1/auth/login") || path.starts_with("/api/v1/auth/register") {
        return Ok(next.run(req).await);
    }

    // Extract token from Authorization header
    let token = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate token
    let claims = validate_token::<S>(token, &state.jwt_secret, &state.storage).await?;
    
    // Check if MFA is required and verified
    if is_mfa_required(&claims.sub, &state.storage).await? && !claims.mfa_verified {
        return Err(StatusCode::FORBIDDEN);
    }

    // Add claims to request extensions for downstream handlers
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

async fn is_mfa_required<S: StorageBackend>(
    user_id: &str,
    storage: &S,
) -> Result<bool, StatusCode> {
    storage.is_mfa_enabled(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn validate_token<S: StorageBackend>(
    token: &str,
    secret: &str,
    storage: &S,
) -> Result<Claims, StatusCode> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Check if token is revoked
    let is_valid = storage.is_token_valid(token).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(token_data.claims)
}

pub fn generate_token(
    user_id: &str,
    roles: Vec<String>,
    secret: &str,
    mfa_verified: bool,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expires_at = now + Duration::hours(24); // 24 hour token lifetime

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expires_at.timestamp() as usize,
        iat: now.timestamp() as usize,
        mfa_verified,
        roles,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}
