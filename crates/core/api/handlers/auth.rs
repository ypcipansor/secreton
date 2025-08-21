//! Authentication handlers

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::Validate;

use crate::{
    api::{error::ApiError, AppState},
    auth::{Claims, LoginRequest, TokenResponse},
};

/// Login request
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequestDto {
    /// Username or email
    #[validate(required, length(min = 3, max = 100))]
    pub username: Option<String>,
    
    /// Password
    #[validate(required, length(min = 8, max = 100))]
    pub password: Option<String>,
    
    /// MFA token (if MFA is required)
    pub mfa_token: Option<String>,
    
    /// MFA code (if MFA is required)
    pub mfa_code: Option<String>,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponseDto {
    /// Authentication token
    pub token: String,
    
    /// Refresh token
    pub refresh_token: String,
    
    /// Token expiration in seconds
    pub expires_in: u64,
    
    /// Whether MFA is required
    pub requires_mfa: bool,
    
    /// MFA token (if MFA is required)
    pub mfa_token: Option<String>,
}

/// Refresh token request
#[derive(Debug, Deserialize, Validate)]
pub struct RefreshTokenRequestDto {
    /// Refresh token
    #[validate(required)]
    pub refresh_token: Option<String>,
}

/// Change password request
#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequestDto {
    /// Current password
    #[validate(required, length(min = 8, max = 100))]
    pub current_password: Option<String>,
    
    /// New password
    #[validate(required, length(min = 8, max = 100))]
    pub new_password: Option<String>,
}

/// Login handler
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequestDto>,
) -> Result<impl IntoResponse, ApiError> {
    let username = payload.username.ok_or_else(|| {
        ApiError::bad_request("Username is required")
    })?;
    
    let password = payload.password.ok_or_else(|| {
        ApiError::bad_request("Password is required")
    })?;

    let result = state
        .auth_service
        .login(&LoginRequest {
            username: &username,
            password: &password,
            mfa_token: payload.mfa_token.as_deref(),
            mfa_code: payload.mfa_code.as_deref(),
        })
        .await?;

    let response = LoginResponseDto {
        token: result.token,
        refresh_token: result.refresh_token.unwrap_or_default(),
        expires_in: result.expires_in,
        requires_mfa: result.requires_mfa,
        mfa_token: result.mfa_token,
    };

    Ok(Json(response))
}

/// Refresh token handler
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshTokenRequestDto>,
) -> Result<impl IntoResponse, ApiError> {
    let refresh_token = payload.refresh_token.ok_or_else(|| {
        ApiError::bad_request("Refresh token is required")
    })?;

    let result = state.auth_service.refresh_token(&refresh_token).await?;

    let response = LoginResponseDto {
        token: result.token,
        refresh_token: result.refresh_token.unwrap_or_default(),
        expires_in: result.expires_in,
        requires_mfa: false,
        mfa_token: None,
    };

    Ok(Json(response))
}

/// Logout handler
pub async fn logout(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    state.auth_service.logout(&claims.jti).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Change password handler
pub async fn change_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChangePasswordRequestDto>,
) -> Result<impl IntoResponse, ApiError> {
    let current_password = payload.current_password.ok_or_else(|| {
        ApiError::bad_request("Current password is required")
    })?;
    
    let new_password = payload.new_password.ok_or_else(|| {
        ApiError::bad_request("New password is required")
    })?;

    state
        .auth_service
        .change_password(&claims.sub, &current_password, &new_password)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
