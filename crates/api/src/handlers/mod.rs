//! HTTP request handlers for the Brankas API.
//! 
//! Provides comprehensive REST endpoints for vault operations,
//! authentication, authorization, and administrative functions.

pub mod auth;
pub mod vault;
pub mod admin;
pub mod health;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};

use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    config::ApiConfig,
    middleware::{auth::AuthMiddleware, rate_limit::RateLimitMiddleware},
    services::ServiceContainer,
    ApiResponse, ApiResult,
};

/// Application state shared across handlers
pub type AppState = Arc<ServiceContainer>;

/// Create the main application router
pub fn create_router(config: &ApiConfig, services: Arc<ServiceContainer>) -> Router {
    let app_state = services.clone();

    // Create API v1 routes
    let api_v1 = Router::new()
        .nest("/auth", auth::create_routes())
        .nest("/vault", vault::create_routes())
        .nest("/admin", admin::create_routes())
        .route("/health", get(health::health_check))
        .route("/version", get(get_version))
        .route("/metrics", get(get_metrics));

    // Main router with middleware stack
    Router::new()
        .nest("/api/v1", api_v1)
        .route("/", get(root_handler))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(TimeoutLayer::new(config.http.timeout))
                .layer(CorsLayer::permissive()) // TODO: Configure properly
                .layer(RateLimitMiddleware::new(&config.rate_limit))
                .layer(AuthMiddleware::new(&config.auth)),
        )
        .with_state(app_state)
}

/// Root endpoint handler
async fn root_handler() -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    let data = serde_json::json!({
        "service": "Brankas API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Advanced Security Vault System",
        "documentation": "/api/v1/docs"
    });

    Ok(Json(ApiResponse::success(data)))
}

/// Get API version information
async fn get_version() -> ApiResult<Json<ApiResponse<VersionInfo>>> {
    let version_info = VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_date: env!("BUILD_DATE").to_string(),
        git_commit: env!("GIT_COMMIT").to_string(),
        rust_version: env!("RUST_VERSION").to_string(),
    };

    Ok(Json(ApiResponse::success(version_info)))
}

/// Get Prometheus metrics
async fn get_metrics(State(_state): State<AppState>) -> Result<String, StatusCode> {
    // Basic metrics implementation
    let metrics = format!(
        "# Brankas API Metrics\n\
         api_requests_total{{method=\"GET\"}} 0\n\
         api_requests_total{{method=\"POST\"}} 0\n\
         api_response_time_seconds{{quantile=\"0.5\"}} 0.1\n\
         api_response_time_seconds{{quantile=\"0.9\"}} 0.2\n\
         api_response_time_seconds{{quantile=\"0.99\"}} 0.5\n"
    );
    Ok(metrics)
}

/// Version information
#[derive(serde::Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub build_date: String,
    pub git_commit: String,
    pub rust_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use crate::config::ApiConfig;

    #[tokio::test]
    async fn test_root_endpoint() {
        let config = ApiConfig::default();
        let services = Arc::new(
            ServiceContainer::new(&config)
                .await
                .expect("Failed to create services")
        );
        
        let app = create_router(&config, services);
        let server = TestServer::new(app).unwrap();
        
        let response = server.get("/").await;
        response.assert_status_ok();
        
        let body: ApiResponse<serde_json::Value> = response.json();
        assert!(body.success);
        assert!(body.data.is_some());
    }

    #[tokio::test]
    async fn test_version_endpoint() {
        let config = ApiConfig::default();
        let services = Arc::new(
            ServiceContainer::new(&config)
                .await
                .expect("Failed to create services")
        );
        
        let app = create_router(&config, services);
        let server = TestServer::new(app).unwrap();
        
        let response = server.get("/api/v1/version").await;
        response.assert_status_ok();
        
        let body: ApiResponse<VersionInfo> = response.json();
        assert!(body.success);
        assert!(body.data.is_some());
    }
}
