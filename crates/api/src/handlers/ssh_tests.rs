use crate::config::ApiConfig;
use crate::handlers::ssh::{CaResponse, SignKeyRequest, SignedKeyResponse};
use crate::services::ApiServiceContainer;
use crate::handlers::create_router;
use crate::ApiResponse;
use axum_test::TestServer;
use std::sync::Arc;
use uuid::Uuid;
use std::collections::HashMap;

async fn server_with_ssh() -> (TestServer, String) {
    // Set root key for crypto service auto-unseal.
    // SAFETY: This test is run serially by the test harness and no other
    // threads are reading this env var concurrently at this point.
    unsafe {
        std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
    }

    let mut config = ApiConfig::default();
    config.auth.jwt.secret = Some("test_secret".to_string());
    config.auth.jwt.issuer = "secreton".to_string();
    config.auth.jwt.audience = "secreton-api".to_string();

    let services = Arc::new(
        ApiServiceContainer::new(&config)
            .await
            .expect("Failed to create services"),
    );

    // Generate mock token for an admin user
    let user_id = Uuid::new_v4();
    let user = secreton_auth::User {
        id: user_id.to_string(),
        username: "admin_user".to_string(),
        email: Some("admin@example.com".to_string()),
        display_name: Some("Admin".to_string()),
        full_name: Some("Admin User".to_string()),
        roles: vec!["admin".to_string()],
        permissions: vec![],
        policies: vec![],
        metadata: HashMap::new(),
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
        is_superuser: true, // Make admin for generate_ca
    };
    let token = services
        .auth
        .generate_token(&user)
        .await
        .expect("Failed to generate token");

    let app = create_router(&config, services.into());
    let server = TestServer::new(app.into_make_service())
        .expect("failed to start test server");
    (server, token)
}

#[tokio::test]
async fn test_ssh_ca_lifecycle() {
    let (server, token) = server_with_ssh().await;
    let auth_header = format!("Bearer {}", token);

    // 1. Get CA (should be 404 Not Found initially)
    let resp = server
        .get("/api/v1/ssh/config/ca")
        .add_header("Authorization", &auth_header)
        .await;
    resp.assert_status_not_found();

    // 2. Generate CA
    let resp = server
        .post("/api/v1/ssh/config/ca")
        .add_header("Authorization", &auth_header)
        .await;
    resp.assert_status_ok();
    let body: ApiResponse<CaResponse> = resp.json();
    assert!(body.success);
    let pub_key = body.data.unwrap().public_key;
    assert!(pub_key.starts_with("ssh-ed25519"));

    // 3. Get CA again
    let resp = server
        .get("/api/v1/ssh/config/ca")
        .add_header("Authorization", &auth_header)
        .await;
    resp.assert_status_ok();
    let body: ApiResponse<CaResponse> = resp.json();
    assert_eq!(body.data.unwrap().public_key, pub_key);

    // 4. Sign a key
    let mock_pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOm6u6SUZToS6W4duuSNo6981+Yw7oTTo1nSInu39f4X test@example.com";
    let sign_req = SignKeyRequest {
        public_key: mock_pub_key.to_string(),
        valid_principals: Some(vec!["ubuntu".to_string()]),
        ttl: Some(3600),
    };

    let resp = server
        .post("/api/v1/ssh/sign")
        .add_header("Authorization", &auth_header)
        .json(&sign_req)
        .await;
    resp.assert_status_ok();
    let body: ApiResponse<SignedKeyResponse> = resp.json();
    assert!(body.success);
    let sign_data = body.data.unwrap();
    assert!(sign_data.signed_key.contains("ssh-ed25519-cert-v01@openssh.com"));
    assert_eq!(sign_data.ttl, 3600);
}
