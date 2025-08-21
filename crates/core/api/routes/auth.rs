//! Authentication routes

use axum::{
    routing::{post, put},
    Router,
};

use crate::api::handlers::auth::*;

/// Returns a router with authentication routes
pub fn router() -> Router {
    Router::new()
        // Login
        .route("/login", post(login))
        // Refresh token
        .route("/refresh", post(refresh_token))
        // Logout
        .route("/logout", post(logout))
        // Change password
        .route("/change-password", put(change_password))
}
