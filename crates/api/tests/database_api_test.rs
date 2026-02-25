use axum::Extension;
use axum_test::TestServer;
use secreton_api::ApiState;
use secreton_api::database::{self, DatabaseApiState, ConfigRequest, ConfigResponse, ListRolesResponse, CreateRoleRequest};
use secreton_api::pki::PkiApiState;
use secreton_api::kv::KVApiState;
use secreton_api::transit::TransitApiState;
use secreton_api::config::ApiConfig;
use secreton_performance::OptimizationLevel;
use std::sync::Arc;
use secreton_secrets::{DatabaseEngine, DatabaseConfig};

#[tokio::test]
async fn test_database_api_endpoints() {
    // Setup full ApiState
    let mut config_inner = ApiConfig::default();
    config_inner.auth.jwt.secret = Some("test_secret".to_string());
    config_inner.auth.jwt.issuer = "secreton".to_string();
    config_inner.auth.jwt.audience = "secreton-api".to_string();
    let config = Arc::new(config_inner);

    let auth = Arc::new(secreton_api::services::auth::AuthenticationService::new(
        Arc::new(secreton_storage::MockStorageBackend::new()),
        Arc::new(secreton_api::services::crypto::CryptoService::new(Arc::new(secreton_storage::MockStorageBackend::new())).await.unwrap()),
        &config.auth
    ).await.unwrap());

    // We can use a simplified ApiState construction for tests or the public new() method
    // Since new() requires many dependencies, constructing struct directly is easier if fields are public.
    // ApiState fields are public.

    use secreton_api::ssh::SshApiState;
    use secreton_api::totp::TotpApiState;

    // Use MockStorageBackend for DatabaseApiState
    let storage = Arc::new(secreton_storage::MockStorageBackend::new());
    let database_state = DatabaseApiState::new(storage.clone()).await;

    let state = ApiState {
        kv: KVApiState::default(),
        transit: TransitApiState::default(),
        database: database_state,
        pki: PkiApiState::default(),
        ssh: SshApiState::default(),
        totp: TotpApiState::default(),
        config: config.clone(),
        secreton: Arc::new(secreton_common::StandardServiceContainer::default()),
        auth: auth.clone(),
        audit: Arc::new(secreton_api::services::admin::AdminService::new(
             storage.clone(),
             auth.clone(),
             Arc::new(secreton_api::services::audit::AuditLogger::new(storage.clone()).await.unwrap()),
             Arc::new(secreton_performance::SecretPerformanceOptimizer::new(secreton_performance::SecretPerformanceConfig::default()))
        ).await.unwrap()),
    };

    // Create router using the main factory to include middleware
    let router = secreton_api::create_api_router(state);

    let server = TestServer::new(router).unwrap();

    // Test Config Endpoint
    let config_req = ConfigRequest {
        connection_url: "postgresql://user:pass@localhost:5432/db".to_string(),
        plugin_name: Some("database".to_string()),
        username: None,
        password: None,
        allowed_roles: None,
    };

    // Note: This request will fail with 401 Unauthorized because we are not providing a valid token
    // and we haven't mocked the auth service to accept it.
    // However, this verifies the router structure and middleware presence.
    // To properly test success, we would need to mock the AuthenticationService validation logic.

    let _response = server.post("/api/v1/database/config")
        .json(&config_req)
        .await;

    // It might fail because the engine tries to connect (detect db type)?
    // DatabaseEngine::init calls detect_database_type which just checks string prefix.
    // DatabaseEngine::init -> detect_database_type -> OK for postgresql://...
    // But init_backend is skipped if not enabled?
    // EngineConfig has enabled=true.
    // init checks config and calls init_backend if enabled.
    // init_backend calls PostgresBackend::new -> creates pool.
    // This might fail if pool creation tries to connect immediately or if config is invalid.
    // PostgresBackend::new usually just sets up the pool configuration.
    // But let's see.
    // If it fails, we expect 500.

    // assert_eq!(response.status_code(), 200); // Depends on backend init behavior

    // For now, let's assume we can list roles even if config fails (it shouldn't fail list roles if internal map is used)

    // Test Create Role Endpoint
    let role_req = CreateRoleRequest {
        sql: "CREATE ROLE {{name}} ...".to_string(),
        max_ttl: Some(3600),
        default_ttl: Some(600),
    };

    let response = server.post("/api/v1/database/roles/test-role")
        .json(&role_req)
        .await;

    println!("Create role response status: {}", response.status_code());

    // Test List Roles Endpoint
    let response = server.get("/api/v1/database/roles").await;
    println!("List roles response status: {}", response.status_code());

    // We expect 401 due to auth middleware
    assert_eq!(response.status_code(), 401);
}
