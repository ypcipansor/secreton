//! Secret management routes

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::api::handlers::secrets::*;

/// Returns a router with secret management routes
pub fn router() -> Router {
    Router::new()
        // List secrets
        .route("/", get(list_secrets))
        // Get secret
        .route("/:path", get(get_secret))
        // Create secret
        .route("/:path", post(create_secret))
        // Update secret
        .route("/:path", put(update_secret))
        // Delete secret
        .route("/:path", delete(delete_secret))
        // List secret versions
        .route("/:path/versions", get(list_secret_versions))
        // Get secret version
        .route("/:path/versions/:version", get(get_secret_version))
        // Rollback secret version
        .post("/:path/rollback/:version", rollback_secret_version)
}
