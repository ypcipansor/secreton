//! HTTP request handlers for the Secreton API.
//! 
//! Provides comprehensive REST endpoints for secreton operations,
//! authentication, authorization, and administrative functions.

pub mod auth;
pub mod secret;
pub mod admin;
pub mod health;
pub mod config;
pub mod sys;

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};

use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    trace::TraceLayer,
};


use crate::middleware::{auth::AuthMiddleware, seal::SealMiddleware, cors::create_cors_layer, rate_limit::RateLimitMiddleware};
use crate::{ApiResponse, ApiResult};
use axum::middleware::{self};
use secreton_config::ApiConfig;
use crate::services::ApiServiceContainer;

/// Application state shared across handlers
pub type AppState = Arc<ApiServiceContainer>;

/// Create the main application router
pub fn create_router(_config: &ApiConfig, services: AppState) -> Router {
    let app_state = services.clone();

    // Create API v1 routes
    let api_v1 = Router::new()
        .nest("/auth", auth::create_routes())
        .nest("/secret", secret::create_routes())
        .nest("/admin", admin::create_routes())
        .nest("/sys", sys::create_routes())
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
                // Use defaults for missing config fields
                .layer(tower_http::timeout::TimeoutLayer::new(std::time::Duration::from_secs(30)))
                .layer(create_cors_layer())
                .layer(middleware::from_fn(RateLimitMiddleware::limit))
                .layer(middleware::from_fn_with_state(app_state.clone(), SealMiddleware::check))
                .layer(middleware::from_fn_with_state(app_state.clone(), AuthMiddleware::authenticate)),
        )
        .with_state(app_state)
}

/// Root endpoint handler
async fn root_handler() -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    let data = serde_json::json!({
        "service": "Secreton API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Advanced Security Secret System",
        "documentation": "/api/v1/docs"
    });

    Ok(Json(ApiResponse::success(data)))
}

/// Get API version information
async fn get_version() -> ApiResult<Json<ApiResponse<VersionInfo>>> {
    let version_info = VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_date: option_env!("BUILD_DATE").unwrap_or("unknown").to_string(),
        git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
        rust_version: option_env!("RUST_VERSION").unwrap_or("unknown").to_string(),
    };

    Ok(Json(ApiResponse::success(version_info)))
}

/// Get Prometheus metrics
async fn get_metrics(State(_state): State<AppState>) -> Result<String, StatusCode> {
    // Basic metrics implementation
    let metrics = "# Secreton API Metrics\n\
         api_requests_total{method=\"GET\"} 0\n\
         api_requests_total{method=\"POST\"} 0\n\
         api_response_time_seconds{quantile=\"0.5\"} 0.1\n\
         api_response_time_seconds{quantile=\"0.9\"} 0.2\n\
         api_response_time_seconds{quantile=\"0.99\"} 0.5\n".to_string();
    Ok(metrics)
}

/// Version information
#[derive(serde::Serialize, serde::Deserialize)]
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
        use secreton_config::ApiConfig as SharedApiConfig;
        
        let mut config = ApiConfig::default();
        config.auth.jwt.secret = Some("test_secret".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();
        let shared_config = SharedApiConfig::default();
        
        let services = Arc::new(
            ApiServiceContainer::new(&config)
                .await
                .expect("Failed to create services")
        );
        
        let app = create_router(&shared_config, services);
        let server = TestServer::new(app.into_make_service()).unwrap();
        
        let response = server.get("/").await;
        response.assert_status_ok();
        
        let body: ApiResponse<serde_json::Value> = response.json();
        assert!(body.success);
        assert!(body.data.is_some());
    }

    #[tokio::test]
    async fn test_version_endpoint() {
        use secreton_config::ApiConfig as SharedApiConfig;

        let mut config = ApiConfig::default();
        config.auth.jwt.secret = Some("test_secret".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();
        let shared_config = SharedApiConfig::default();

        let services = Arc::new(
            ApiServiceContainer::new(&config)
                .await
                .expect("Failed to create services")
        );
        
        let app = create_router(&shared_config, services);
        let server = TestServer::new(app.into_make_service()).unwrap();
        
        let response = server.get("/api/v1/version").await;
        response.assert_status_ok();
        
        let body: ApiResponse<VersionInfo> = response.json();
        assert!(body.success);
        assert!(body.data.is_some());
    }
}
