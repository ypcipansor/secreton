//! API route definitions

mod auth;
mod health;
mod mfa;
mod public;
mod secrets;

use axum::Router;
use std::sync::Arc;

use crate::api::AppState;

/// Returns a router with all protected API routes
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Auth routes
        .nest("/auth", auth::router())
        // MFA routes
        .nest("/mfa", mfa::router())
        // Secrets routes
        .nest("/secrets", secrets::router())
}

/// Returns a router with public API routes
pub fn public_router() -> Router<Arc<AppState>> {
    public::public_router()
}
