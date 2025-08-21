//! Public API routes (no authentication required)

use axum::{
    routing::{get, post},
    Router,
};

use crate::api::handlers::{
    auth::{login, refresh_token},
    health::health_check,
    mfa::verify_mfa_login,
};

/// Returns a router with public routes
pub fn public_router() -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_check))
        // Authentication
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh_token))
        // MFA verification during login
        .route("/mfa/verify-login", post(verify_mfa_login))
}
