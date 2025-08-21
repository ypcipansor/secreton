//! MFA API routes

use axum::{
    routing::{get, post},
    Router,
};

use crate::api::handlers::mfa::*;

/// Returns a router with all MFA-related routes
pub fn router() -> Router {
    Router::new()
        // Get MFA status
        .route("/mfa", get(get_mfa_status))
        // Start MFA setup
        .route("/mfa/setup", post(start_mfa_setup))
        // Verify MFA setup
        .route("/mfa/verify", post(verify_mfa))
        // Generate new recovery codes
        .route("/mfa/recovery-codes", post(generate_recovery_codes))
        // Disable MFA
        .route("/mfa", axum::routing::delete(disable_mfa))
        // Verify MFA during login
        .route("/mfa/verify-login", post(verify_mfa_login))
}

/// Returns a router with public MFA routes (no auth required)
pub fn public_router() -> Router {
    Router::new()
        // Verify MFA during login (public endpoint)
        .route("/mfa/verify-login", post(verify_mfa_login))
}
