//! Brankas API Library
//!
//! Simple HTTP API for the Brankas transit engine

use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};

pub mod auth;
pub mod config;
pub mod kv;
pub mod middleware;
// TODO: Update TLS optimization module for rustls 0.23 API changes
// pub mod tls_optimization;
pub mod transit;

pub use kv::{create_kv_router, KVApiState, KVEngine};
pub use transit::{create_transit_router, TransitApiState};
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

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
    pub build_date: String,
    pub git_commit: String,
}

#[derive(Serialize, Deserialize)]
pub struct TlsMetricsResponse {
    pub total_handshakes: u64,
    pub successful_handshakes: u64,
    pub session_resumptions: u64,
    pub handshake_failures: u64,
    pub average_handshake_time_ms: u64,
    pub success_rate_percent: f64,
    pub resumption_rate_percent: f64,
}

/// Create the main API router
pub fn create_api_router(state: ApiState) -> Router {
    Router::new()
        // System endpoints
        .route("/health", get(health_check))
        .route("/version", get(get_version))
        .route("/tls-metrics", get(get_tls_metrics))
        // Transit engine endpoints
        .nest(
            "/v1/transit",
            create_transit_router().with_state(state.transit.clone()),
        )
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
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_date: "2024".to_string(),
        git_commit: "unknown".to_string(),
    })
}

pub async fn get_tls_metrics() -> Json<TlsMetricsResponse> {
    // TODO: Re-enable when tls_optimization module is updated
    // let metrics = tls_optimization::get_tls_metrics();
    Json(TlsMetricsResponse {
        total_handshakes: 0,
        successful_handshakes: 0,
        session_resumptions: 0,
        handshake_failures: 0,
        average_handshake_time_ms: 0,
        success_rate_percent: 0.0,
        resumption_rate_percent: 0.0,
    })
}
