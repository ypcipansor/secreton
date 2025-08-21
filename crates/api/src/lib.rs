//! Brankas API Library
//! 
//! Simple HTTP API for the Brankas transit engine

use axum::{
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use std::collections::HashMap;

pub mod transit;
pub mod kv;
pub mod auth;
pub mod middleware;

pub use transit::{TransitApiState, create_transit_router};
pub use kv::{KVApiState, create_kv_router};

// Simple API state
#[derive(Clone)]
pub struct ApiState {
    pub transit: TransitApiState,
    pub kv: KVApiState,
}

#[derive(Clone)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8200,
        }
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
}

#[derive(Serialize)]
pub struct VersionResponse {
    pub version: String,
    pub build_date: String,
    pub git_commit: String,
}

/// Create the main API router
pub fn create_api_router(state: ApiState) -> Router {
    Router::new()
        // System endpoints
        .route("/health", get(health_check))
        .route("/version", get(get_version))
        
        // Transit engine endpoints
        .nest("/v1/transit", create_transit_router().with_state(state.transit.clone()))
        
        // KV secrets engine endpoints
        .nest("/v1", create_kv_router(state.kv.clone()))
}

pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        version: "1.0.0".to_string(),
    })
}

pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: "1.0.0".to_string(),
        build_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        git_commit: "unknown".to_string(),
    })
}