//! Comprehensive API crate tests
//!
//! Tests for HTTP API handlers, middleware, services, and integration

use anyhow::Result;
use axum::{
    body::Body,
    http::{Method, StatusCode},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use secreton_api::{
    auth::{AuthConfig, AuthMethod},
    config::{ApiConfig, ServerConfig},
    middleware::{cors::CorsLayer, logging::LoggingLayer, security::SecurityLayer},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

#[cfg(test)]
mod api_tests {
    use super::*;

    async fn create_test_app() -> Router {
        // Create test configuration
        let api_config = ApiConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8200,
                tls_cert_file: None,
                tls_key_file: None,
                enable_mtls: false,
            },
            auth: AuthConfig {
                method: AuthMethod::Jwt,
                jwt_secret: "test-secret-key-for-jwt-signing".to_string(),
                jwt_expiration: 3600,
                ldap_config: None,
                oidc_config: None,
            },
            cors: Default::default(),
            logging: Default::default(),
            security: Default::default(),
        };

        // Create router with middleware layers
        let app = Router::new()
            .layer(CorsLayer::new())
            .layer(LoggingLayer::new())
            .layer(SecurityLayer::new(&api_config));

        app
    }

    #[tokio::test]
    async fn test_health_check_endpoint() -> Result<()> {
        let app = create_test_app().await;

        // Test health check endpoint
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await?.to_bytes();
        let body_str = String::from_utf8(body.to_vec())?;

        let health_response: Value = serde_json::from_str(&body_str)?;
        assert_eq!(health_response["status"], "healthy");

        Ok(())
    }

    #[tokio::test]
    async fn test_version_endpoint() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/version")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await?.to_bytes();
        let body_str = String::from_utf8(body.to_vec())?;

        let version_response: Value = serde_json::from_str(&body_str)?;
        assert!(version_response.get("version").is_some());
        assert!(version_response.get("build").is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_middleware() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/health")
                    .header("Origin", "http://localhost:3000")
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())?,
            )
            .await?;

        // CORS preflight should return OK for allowed origins
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("access-control-allow-origin"));

        Ok(())
    }

    #[tokio::test]
    async fn test_logging_middleware() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header("User-Agent", "test-client")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        // Logging middleware should not interfere with normal operation

        Ok(())
    }

    #[tokio::test]
    async fn test_security_headers_middleware() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        // Check for security headers
        assert!(response.headers().contains_key("x-content-type-options"));
        assert!(response.headers().contains_key("x-frame-options"));
        assert!(response.headers().contains_key("x-xss-protection"));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_route() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/nonexistent-route")
                    .body(Body::empty())?,
            )
            .await?;

        // Should return 404 for non-existent routes
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn test_method_not_allowed() -> Result<()> {
        let app = create_test_app().await;

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::DELETE)
                    .uri("/health")
                    .body(Body::empty())?,
            )
            .await?;

        // DELETE method not allowed on health endpoint
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        Ok(())
    }
}

#[cfg(test)]
mod api_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_api_server_initialization() -> Result<()> {
        // Test that API server can be initialized without errors
        let config = ApiConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8200,
                tls_cert_file: None,
                tls_key_file: None,
                enable_mtls: false,
            },
            auth: AuthConfig {
                method: AuthMethod::Jwt,
                jwt_secret: "test-secret".to_string(),
                jwt_expiration: 3600,
                ldap_config: None,
                oidc_config: None,
            },
            cors: Default::default(),
            logging: Default::default(),
            security: Default::default(),
        };

        // Configuration should be valid
        assert_eq!(config.server.port, 8200);
        assert_eq!(config.auth.method, AuthMethod::Jwt);

        Ok(())
    }

    #[tokio::test]
    async fn test_middleware_stack() -> Result<()> {
        // Test that all middleware layers can be created and stacked
        let config = ApiConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8200,
                tls_cert_file: None,
                tls_key_file: None,
                enable_mtls: false,
            },
            auth: AuthConfig {
                method: AuthMethod::Jwt,
                jwt_secret: "test-secret".to_string(),
                jwt_expiration: 3600,
                ldap_config: None,
                oidc_config: None,
            },
            cors: Default::default(),
            logging: Default::default(),
            security: Default::default(),
        };

        // All middleware should initialize without errors
        let cors_layer = CorsLayer::new();
        let logging_layer = LoggingLayer::new();
        let security_layer = SecurityLayer::new(&config);

        assert!(cors_layer.is_ok());
        assert!(logging_layer.is_ok());
        assert!(security_layer.is_ok());

        Ok(())
    }
}
