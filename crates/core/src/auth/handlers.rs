//! Authentication HTTP handlers for Secreton

use crate::server::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    response::Json,
};
use axum_extra::headers::{Authorization, authorization::Bearer};
use axum_extra::TypedHeader;
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
    State(state): State<Arc<AppState>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    // Extract token from Authorization header
    let token = bearer.token();

    match state.auth_service.validate_token(token).await {
        Ok(user_info) => {
            // Revoke the token by adding it to blacklist
            if let Err(e) = state.auth_service.revoke_token(token).await {
                tracing::warn!("Failed to revoke token for user {}: {:?}", user_info.username, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Failed to revoke token"})),
                );
            }

            tracing::info!("User {} logged out successfully", user_info.username);
            (
                StatusCode::OK,
                Json(serde_json::json!({"message": "Logged out successfully"})),
            )
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid token"})),
        ),
    }
}

/// Get current user info
pub async fn me(
    State(state): State<Arc<AppState>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    let token = bearer.token();

    match state.auth_service.validate_token(token).await {
        Ok(user_info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": user_info.id.unwrap_or_default(),
                "username": user_info.username,
                "roles": user_info.roles
            })),
        ),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid token"})),
        ),
    }
}

/// Change password handler
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let token = bearer.token();

    match state.auth_service.validate_token(token).await {
        Ok(user_info) => {
            match state.auth_service.change_password(
                &user_info.id.unwrap_or_default(),
                &req.current_password,
                &req.new_password,
            ).await {
                Ok(_) => {
                    tracing::info!("User {} changed password successfully", user_info.username);
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({"message": "Password changed successfully"})),
                    )
                }
                Err(e) => {
                    tracing::warn!("Password change failed for user {}: {:?}", user_info.username, e);
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "Failed to change password"})),
                    )
                }
            }
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid token"})),
        ),
    }
}

/// Register user handler
pub async fn register_user(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterUserRequest>,
) -> impl IntoResponse {
    // Validate input
    if req.username.is_empty() || req.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Username and password are required"})),
        );
    }

    // Check password strength (basic validation)
    if req.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Password must be at least 8 characters long"})),
        );
    }

    match state.auth_service.register_user(
        &req.username,
        &req.password,
        req.email.as_deref(),
        &["user".to_string()], // Default role
    ).await {
        Ok(user_info) => {
            tracing::info!("User {} registered successfully", req.username);
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "message": "User registered successfully",
                    "user_id": user_info.id
                })),
            )
        }
        Err(e) => {
            tracing::warn!("User registration failed for {}: {:?}", req.username, e);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Failed to register user"})),
            )
        }
    }
}

/// List users handler
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    let token = bearer.token();

    match state.auth_service.validate_token(token).await {
        Ok(user_info) => {
            // Check if user has admin role
            if !user_info.roles.contains(&"admin".to_string()) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "Admin role required to list users"})),
                );
            }

            match state.auth_service.list_users().await {
                Ok(users) => {
                    let user_responses: Vec<serde_json::Value> = users.into_iter().map(|user| {
                        serde_json::json!({
                            "id": user.id.unwrap_or_default(),
                            "username": user.username,
                            "roles": user.roles
                        })
                    }).collect();
                    (StatusCode::OK, Json(serde_json::json!(user_responses)))
                }
                Err(e) => {
                    tracing::error!("Failed to list users: {:?}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Failed to list users"})),
                    )
                }
            }
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid token"})),
        ),
    }
}
