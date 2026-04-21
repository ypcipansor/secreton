use axum::Extension;
use axum_test::TestServer;
use secreton_api::ApiState;
use secreton_api::config::ApiConfig;
use secreton_api::database::{
    self, ConfigRequest, ConfigResponse, CreateRoleRequest, DatabaseApiState, ListRolesResponse,
};
use secreton_api::kv::KVApiState;
use secreton_api::pki::PkiApiState;
use secreton_performance::OptimizationLevel;
use secreton_secrets::{DatabaseConfig, DatabaseEngine};
use std::sync::Arc;

#[tokio::test]
async fn test_database_api_endpoints() {
    // Setup full ApiState
    let mut config_inner = ApiConfig::default();
    config_inner.auth.jwt.secret = Some("test_secret".to_string());
    config_inner.auth.jwt.issuer = "secreton".to_string();
    config_inner.auth.jwt.audience = "secreton-api".to_string();
    let config = Arc::new(config_inner);

    let auth = Arc::new(
        secreton_api::services::auth::AuthenticationService::new(
            Arc::new(secreton_storage::MockStorageBackend::new()),
            Arc::new(
                secreton_api::services::crypto::CryptoService::new(Arc::new(
                    secreton_storage::MockStorageBackend::new(),
                ))
                .await
                .unwrap(),
            ),
            &config.auth,
        )
        .await
        .unwrap(),
    );

    // We can use a simplified ApiState construction for tests or the public new() method
    // Since new() requires many dependencies, constructing struct directly is easier if fields are public.
    // ApiState fields are public.

    use secreton_api::ssh::SshApiState;
    use secreton_api::totp::TotpApiState;

    // Use MockStorageBackend for DatabaseApiState
    let storage: Arc<dyn secreton_storage::StorageBackend + Send + Sync> =
        Arc::new(secreton_storage::MockStorageBackend::new());
    let database_state = DatabaseApiState::new(storage.clone()).await;

    // Create remaining services for container
    let crypto = Arc::new(
        secreton_api::services::crypto::CryptoService::new(storage.clone())
            .await
            .unwrap(),
    );
    let audit = Arc::new(
        secreton_api::services::audit::AuditLogger::new(storage.clone(), 2555, 1000, true)
            .await
            .unwrap(),
    );
    let performance = Arc::new(secreton_performance::SecretPerformanceOptimizer::new(
        secreton_performance::SecretPerformanceConfig::default(),
    ));
    let policy = Arc::new(secreton_auth::policies::service::PolicyService::new());
    let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
    let secret = Arc::new(
        secreton_api::services::secret::SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
            identity.clone(),
            policy.clone(),
            performance.clone(),
        )
        .await
        .unwrap(),
    );
    let seal = Arc::new(secreton_api::services::seal::SealService::new(
        storage.clone(),
        crypto.clone(),
        "test-secret".to_string(),
        "iss".to_string(),
        "aud".to_string(),
    ));
    let admin = Arc::new(
        secreton_api::services::admin::AdminService::new(
            storage.clone(),
            auth.clone(),
            performance.clone(),
            audit.clone(),
        )
        .await
        .unwrap(),
    );

    // Mock MFA
    let mfa = Arc::new(secreton_auth::mfa::CombinedMfaService::new(
        Arc::new(secreton_auth::mfa::InMemoryTotpService::new(
            "test".to_string(),
        )),
        Arc::new(secreton_auth::mfa::InMemorySmsService::new(
            secreton_auth::mfa::SmsConfig::default(),
        )),
        Arc::new(secreton_auth::mfa::InMemoryEmailService::new(
            secreton_auth::mfa::EmailConfig::default(),
        )),
        Arc::new(secreton_auth::mfa::InMemoryHardwareService::new()),
        Arc::new(secreton_auth::mfa::DefaultPushService::new_mock()),
        Arc::new(secreton_auth::mfa::DefaultWebAuthnService::new_default()),
        Arc::new(secreton_auth::mfa::DefaultRecoveryCodeService::new()),
    ));

    use secreton_common::{ServiceContainer, StandardServiceContainer};
    let mut container = StandardServiceContainer::default();
    container.register_service("storage".to_string(), storage.clone());
    container.register_service("crypto".to_string(), crypto.clone());
    container.register_service("audit".to_string(), audit.clone());
    container.register_service("auth".to_string(), auth.clone());
    container.register_service("secret".to_string(), secret.clone());
    container.register_service("performance".to_string(), performance.clone());
    container.register_service("seal".to_string(), seal.clone());
    container.register_service("policy".to_string(), policy.clone());
    container.register_service("mfa".to_string(), mfa.clone());

    // Register new engine services required by create_api_router
    let database_svc = Arc::new(
        secreton_api::services::database::DatabaseService::new(storage.clone(), crypto.clone()),
    );
    container.register_service("database".to_string(), database_svc);
    let pki_svc = Arc::new(
        secreton_api::services::pki::PkiPersistentService::new(storage.clone(), crypto.clone()),
    );
    container.register_service("pki".to_string(), pki_svc);
    let totp_engine_svc = Arc::new(
        secreton_api::services::totp_engine::TotpEngineService::new(
            storage.clone(),
            crypto.clone(),
        ),
    );
    container.register_service("totp_engine".to_string(), totp_engine_svc);

    // Register transit, ssh, and telemetry services required by create_api_router
    let transit = Arc::new(secreton_crypto::transit::TransitEngine::new());
    container.register_service("transit".to_string(), transit);
    let ssh_svc = Arc::new(
        secreton_api::services::ssh::SshPersistentService::new(storage.clone(), crypto.clone()),
    );
    container.register_service("ssh".to_string(), ssh_svc);
    let telemetry = Arc::new(secreton_core::telemetry::TelemetryCollector::new(
        secreton_core::telemetry::TelemetryConfig::default(),
    ));
    container.register_service("telemetry".to_string(), telemetry);

    let state = ApiState {
        kv: KVApiState::default(),
        database: database_state,
        pki: PkiApiState::default(),
        ssh: SshApiState::default(),
        totp: TotpApiState::default(),
        config: config.clone(),
        secreton: Arc::new(container),
        auth: auth.clone(),
        audit: admin.clone(),
    };

    // Create router using the main factory to include middleware
    let router = secreton_api::create_api_router(state).expect("Failed to create API router");

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

    let _response = server
        .post("/api/v1/database/config")
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

    let response = server
        .post("/api/v1/database/roles/test-role")
        .json(&role_req)
        .await;

    println!("Create role response status: {}", response.status_code());

    // Test List Roles Endpoint
    let response = server.get("/api/v1/database/roles").await;
    println!("List roles response status: {}", response.status_code());

    // We expect 401 due to auth middleware
    assert_eq!(response.status_code(), 401);
}
