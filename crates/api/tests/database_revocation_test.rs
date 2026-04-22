use axum_test::TestServer;
use secreton_api::ApiState;
use secreton_api::config::ApiConfig;
use secreton_api::database::DatabaseApiState;
use secreton_api::kv::KVApiState;
use secreton_api::pki::PkiApiState;
use secreton_api::ssh::SshApiState;
use secreton_api::totp::TotpApiState;
use secreton_common::{ServiceContainer, StandardServiceContainer};
use secreton_secrets_database::{DatabaseConfig, DatabaseRole};
use secreton_storage::StorageBackend;
use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;

#[tokio::test]
async fn test_database_lease_revocation_flow() {
    // Setup environment
    let mut config_inner = ApiConfig::default();
    config_inner.auth.jwt.secret = Some("test_secret_32_bytes_long_required_!!".to_string());
    config_inner.auth.jwt.issuer = "secreton".to_string();
    config_inner.auth.jwt.audience = "secreton-api".to_string();
    let config = Arc::new(config_inner);

    let storage = Arc::new(secreton_storage::MockStorageBackend::new());

    let crypto = Arc::new(
        secreton_api::services::crypto::CryptoService::new(storage.clone())
            .await
            .unwrap(),
    );
    // Initialize crypto root key
    crypto.set_root_key(vec![0u8; 32]).await.unwrap();

    let audit = Arc::new(
        secreton_api::services::audit::AuditLogger::new(storage.clone(), 2555, 1000, true)
            .await
            .unwrap(),
    );

    let auth = Arc::new(
        secreton_api::services::auth::AuthenticationService::new(
            storage.clone(),
            crypto.clone(),
            &config.auth,
        )
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

    let mfa = Arc::new(secreton_auth::mfa::CombinedMfaService::new(
        Arc::new(secreton_auth::mfa::InMemoryTotpService::new("test".to_string())),
        Arc::new(secreton_auth::mfa::InMemorySmsService::new(Default::default())),
        Arc::new(secreton_auth::mfa::InMemoryEmailService::new(Default::default())),
        Arc::new(secreton_auth::mfa::InMemoryHardwareService::new()),
        Arc::new(secreton_auth::mfa::DefaultPushService::new_mock()),
        Arc::new(secreton_auth::mfa::DefaultWebAuthnService::new_default()),
        Arc::new(secreton_auth::mfa::DefaultRecoveryCodeService::new()),
    ));

    let database_svc = Arc::new(
        secreton_api::services::database::DatabaseService::new(storage.clone(), crypto.clone()),
    );

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
    container.register_service("database".to_string(), database_svc.clone());
    container.register_service("pki".to_string(), Arc::new(secreton_api::services::pki::PkiPersistentService::new(storage.clone(), crypto.clone())));
    container.register_service("totp_engine".to_string(), Arc::new(secreton_api::services::totp_engine::TotpEngineService::new(storage.clone(), crypto.clone())));
    container.register_service("transit".to_string(), Arc::new(secreton_crypto::transit::TransitEngine::new()));
    container.register_service("ssh".to_string(), Arc::new(secreton_api::services::ssh::SshPersistentService::new(storage.clone(), crypto.clone())));
    container.register_service("telemetry".to_string(), Arc::new(secreton_core::telemetry::TelemetryCollector::new(Default::default())));

    let state = ApiState {
        kv: KVApiState::default(),
        database: DatabaseApiState::new(storage.clone()).await,
        pki: PkiApiState::default(),
        ssh: SshApiState::default(),
        totp: TotpApiState::default(),
        config: config.clone(),
        secreton: Arc::new(container),
        auth: auth.clone(),
        audit: admin.clone(),
    };

    let router = secreton_api::create_api_router(state).expect("Failed to create API router");
    let server = TestServer::new(router).unwrap();

    // Create admin user and token
    let admin_user = secreton_auth::User {
        id: Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        email: Some("admin@example.com".to_string()),
        display_name: Some("Admin".to_string()),
        full_name: Some("Admin User".to_string()),
        roles: vec!["admin".to_string()],
        permissions: vec![],
        policies: vec!["default".to_string()],
        metadata: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        failed_login_attempts: 0,
        locked_until: None,
        last_login: None,
        mfa_enabled: false,
        mfa_secret: None,
        password_hash: "".to_string(),
        disabled: false,
        enabled: true,
        is_active: true,
        is_superuser: true,
    };
    let token = auth.generate_token(&admin_user).await.unwrap();

    // Configure database engine (Mocked PostgreSQL)
    let db_config = DatabaseConfig {
        connection_url: "postgresql://localhost:5432/test".to_string(),
        ..Default::default()
    };

    let res = server.post("/api/v1/database/config")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&db_config)
        .await;
    res.assert_status_ok();

    // Add a role
    let role = DatabaseRole {
        sql: "CREATE ROLE {{name}};".to_string(),
        default_ttl: 3600,
        max_ttl: 86400,
    };
    let res = server.post("/api/v1/database/roles/test-role")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&role)
        .await;
    res.assert_status_ok();

    // Manually seed a lease for revocation testing (since actual cred generation requires real DB)
    let lease_id = "db_test-role_testlease";
    let lease_data = json!({
        "lease_id": lease_id,
        "role": "test-role",
        "username": "s_testuser",
        "created_at": chrono::Utc::now().to_rfc3339(),
        "lease_duration": 3600,
    });
    let lease_json = serde_json::to_vec(&lease_data).unwrap();
    let encrypted_lease = crypto.encrypt_data(&lease_json).await.unwrap();
    let lease_entry = secreton_storage::SecretEntry::new(
        format!("sys/database/leases/{}", lease_id),
        encrypted_lease,
        secreton_storage::EncryptionMetadata::default(),
        secreton_storage::SecurityLevel::Secret,
        Uuid::nil(),
    );
    storage.store(&lease_entry).await.unwrap();

    // Verify lease exists
    let res = server.get("/api/v1/database/leases")
        .add_header("Authorization", format!("Bearer {}", token))
        .await;
    res.assert_status_ok();
    let body: secreton_api::ApiResponse<Vec<serde_json::Value>> = res.json();
    assert!(body.data.unwrap().iter().any(|l| l["lease_id"] == lease_id));

    // Revoke lease
    // Note: This will call engine.revoke_credentials which tries to connect to PostgreSQL.
    // Since we don't have a real PostgreSQL running, it might fail if get_pg_pool fails.
    // However, DatabaseEngine::revoke_credentials calls get_pg_pool, which tries to parse config.
    // If it fails to connect, it will return error.

    let res = server.delete(&format!("/api/v1/database/leases/{}", lease_id))
        .add_header("Authorization", format!("Bearer {}", token))
        .await;

    // We expect failure here because no real PostgreSQL, but we want to see it reached the revocation logic.
    // Status should be 500 (Internal) because DatabaseServiceError::Internal is mapped to 500.
    assert_eq!(res.status_code(), 500);
    let body: secreton_api::ApiResponse<()> = res.json();
    assert!(body.error.unwrap().contains("Database revocation failed"));
}
