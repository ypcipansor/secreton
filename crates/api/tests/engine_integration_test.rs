use std::sync::Arc;
use axum_test::TestServer;
use serde_json::json;
use secreton_api::config::ApiConfig;
use secreton_api::services::ApiServiceContainer;
use secreton_api::handlers::{create_router, AppState};

async fn setup_test_server() -> TestServer {
    // Set root key for crypto service auto-unseal.
    // SAFETY: This is only called during test setup before any concurrent
    // threads read this variable.  In practice the env var should be set
    // outside the process (e.g. in CI config) to avoid the unsoundness of
    // set_var in multi-threaded programs.
    unsafe { std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!") };

    let mut config = ApiConfig::default();
    config.auth.jwt.secret = Some("test_secret".to_string());
    config.auth.jwt.issuer = "secreton".to_string();
    config.auth.jwt.audience = "secreton-api".to_string();

    let services = ApiServiceContainer::new(&config).await.expect("Failed to create services");
    let app_state: AppState = Arc::new(services).into();

    let app = create_router(&config, app_state);
    TestServer::new(app).expect("Failed to create test server")
}

#[tokio::test]
async fn test_database_engine_lifecycle() {
    let server = setup_test_server().await;

    let config_payload = json!({
        "connection_url": "postgresql://user:pass@localhost:5432/db",
        "verify_connection": false
    });

    let res = server.post("/api/v1/database/config").json(&config_payload).await;
    // We expect 401 Unauthorized because we didn't provide a token, but the route should exist (not 404)
    assert_ne!(res.status_code(), 404);
}

#[tokio::test]
async fn test_pki_engine_lifecycle() {
    let server = setup_test_server().await;

    let ca_payload = json!({
        "common_name": "Test Root CA",
        "organization": "Test Org"
    });
    let res = server.post("/api/v1/pki/root/generate").json(&ca_payload).await;
    assert_ne!(res.status_code(), 404);
}

#[tokio::test]
async fn test_totp_engine_lifecycle() {
    let server = setup_test_server().await;

    let res = server.get("/api/v1/totp/keys").await;
    assert_ne!(res.status_code(), 404);
}
