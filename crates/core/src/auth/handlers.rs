//! Authentication HTTP handlers for Secreton

use crate::server::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Login request payload
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Refresh token request
#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Change password request
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Register user request
#[derive(Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

/// User info response
#[derive(Serialize)]
pub struct UserInfoResponse {
    pub id: String,
    pub username: String,
    pub roles: Vec<String>,
}

/// Login handler
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .auth_service
        .login(&req.username, &req.password, "password")
        .await
    {
        Ok(token_pair) => {
            let response = serde_json::json!({
                "access_token": token_pair.access_token,
                "refresh_token": token_pair.refresh_token,
                "expires_in": token_pair.expires_in as i64
            });
            (StatusCode::OK, Json(response))
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid credentials"})),
        ),
    }
}

/// Refresh token handler
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.auth_service.refresh_token(&req.refresh_token).await {
        Ok(token_pair) => {
            let response = serde_json::json!({
                "access_token": token_pair.access_token,
                "refresh_token": token_pair.refresh_token,
                "expires_in": token_pair.expires_in as i64
            });
            (StatusCode::OK, Json(response))
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid refresh token"})),
        ),
    }
}

/// Logout handler
pub async fn logout(
    State(_state): State<Arc<AppState>>,
    // TODO: Extract and revoke token
) -> impl IntoResponse {
    // For now, just return success
    // In production, revoke the token
    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "Logged out"})),
    )
}

/// Get current user info
pub async fn me(
    State(_state): State<Arc<AppState>>,
    // TODO: Extract token and get user info
) -> impl IntoResponse {
    // For now, return mock user info
    // In production, validate token and return user data
    let user_info = UserInfoResponse {
        id: "user-id".to_string(),
        username: "username".to_string(),
        roles: vec!["user".to_string()],
    };
    (StatusCode::OK, Json(user_info))
}

/// Change password handler
pub async fn change_password(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<ChangePasswordRequest>,
    // TODO: Extract user from token and change password
) -> impl IntoResponse {
    // For now, just return success
    // In production, validate current password and update
    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "Password changed"})),
    )
}

/// Register user handler
pub async fn register_user(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<RegisterUserRequest>,
    // TODO: Create new user
) -> impl IntoResponse {
    // For now, just return success
    // In production, create user account
    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "User registered"})),
    )
}

/// List users handler
pub async fn list_users(
    State(_state): State<Arc<AppState>>,
    // TODO: Check admin permissions and list users
) -> impl IntoResponse {
    // For now, return mock users
    // In production, return actual users
    let users = vec![
        UserInfoResponse {
            id: "1".to_string(),
            username: "admin".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        UserInfoResponse {
            id: "2".to_string(),
            username: "user".to_string(),
            roles: vec!["user".to_string()],
        },
    ];
    (StatusCode::OK, Json(users))
}
