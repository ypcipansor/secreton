//! Authentication middleware

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    headers::{authorization::Bearer, Authorization, HeaderMapExt},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    RequestPartsExt, TypedHeader,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    api::{error::ApiError, AppState},
    auth::{Claims, MFA_CLAIM},
};

/// Middleware to verify JWT tokens and MFA status
pub async fn auth_middleware<B>(
    State(state): State<Arc<AppState>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next<B>,
) -> Result<Response, ApiError> {
    // Skip auth for public routes
    if is_public_path(req.uri().path()) {
        return Ok(next.run(req).await);
    }

    // Extract token from Authorization header
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("Missing or invalid Authorization header"))?;

    // Decode and validate token
    let claims = decode_token(token, &state.config.auth.jwt_secret)?;
    
    // Check if MFA is required but not verified
    if is_protected_path(req.uri().path()) && !claims.mfa_verified() {
        return Err(ApiError::forbidden("MFA verification required"));
    }

    // Add claims to request extensions for use in handlers
    req.extensions_mut().insert(claims);
    
    Ok(next.run(req).await)
}

/// Check if the path is public (no auth required)
fn is_public_path(path: &str) -> bool {
    path.starts_with("/v1/auth/") || 
    path.starts_with("/v1/health") ||
    path.starts_with("/v1/mfa/verify-login")
}

/// Check if the path requires MFA verification
fn is_protected_path(path: &str) -> bool {
    // Add paths that require MFA verification
    path.starts_with("/v1/secrets") ||
    path.starts_with("/v1/keys")
}

/// Decode and validate a JWT token
fn decode_token(token: &str, secret: &str) -> Result<Claims, ApiError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}

/// Extractor for authenticated users with MFA verification
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub Claims);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Extract token from Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| ApiError::unauthorized("Missing or invalid Authorization header"))?;

        // Decode and validate token
        let claims = decode_token(bearer.token(), &state.config.auth.jwt_secret)?;

        // Check if MFA is required but not verified
        if is_protected_path(&parts.uri.to_string()) && !claims.mfa_verified() {
            return Err(ApiError::forbidden("MFA verification required"));
        }

        Ok(AuthenticatedUser(claims))
    }
}

/// Extractor for users that require MFA verification
#[derive(Debug, Clone)]
pub struct MfaVerifiedUser(pub Claims);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for MfaVerifiedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Extract token from Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| ApiError::unauthorized("Missing or invalid Authorization header"))?;

        // Decode and validate token
        let claims = decode_token(bearer.token(), &state.config.auth.jwt_secret)?;

        // Verify MFA is enabled and verified
        if !claims.mfa_verified() {
            return Err(ApiError::forbidden("MFA verification required"));
        }

        Ok(MfaVerifiedUser(claims))
    }
}
