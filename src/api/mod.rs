//! API module for Brankas Adhyaksa

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod routes;

use std::sync::Arc;

use axum::Router;
use tokio::sync::RwLock;

use crate::{
    auth::AuthService,
    config::Config,
    policy::PolicyEngine,
    secrets::SecretsService,
};

/// Application state shared across all routes
#[derive(Clone)]
pub struct AppState {
    /// Configuration
    pub config: Arc<Config>,
    
    /// Authentication service
    pub auth_service: Arc<AuthService>,
    
    /// Secrets service
    pub secrets_service: Arc<SecretsService>,
    
    /// Policy engine for authorization
    pub policy_engine: Arc<PolicyEngine>,
}

impl AppState {
    /// Create a new AppState instance
    pub fn new(
        config: Config,
        auth_service: AuthService,
        secrets_service: SecretsService,
        policy_engine: PolicyEngine,
    ) -> Self {
        Self {
            config: Arc::new(config),
            auth_service: Arc::new(auth_service),
            secrets_service: Arc::new(secrets_service),
            policy_engine: Arc::new(policy_engine),
        }
    }
}

/// Create the API router with all routes
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Public routes (no auth required)
        .nest("/v1", routes::public_router())
        // Protected routes (auth required)
        .nest(
            "/v1",
            routes::router()
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    middleware::auth::auth_middleware,
                ))
                .layer(axum::middleware::from_fn(middleware::cors::cors_middleware))
                .with_state(state),
        )
}