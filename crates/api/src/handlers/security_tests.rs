#[cfg(test)]
mod tests {
    use crate::config::ApiConfig;
    use crate::handlers::{AppState, create_router};
    use crate::services::ApiServiceContainer;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn setup_test_app() -> axum::Router {
        let mut config = ApiConfig::default();
        config.auth.jwt.secret =
            Some("test_secret_key_for_security_testing_purposes_only".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();

        let container = ApiServiceContainer::new(&config).await.unwrap();

        // Unseal the container for testing
        let root_key = vec![0u8; 32];
        container.crypto.set_root_key(root_key).await.unwrap();

        // Create a mock session in storage so the token is accepted
        let jti = "test-jti";
        let user_id = "00000000-0000-0000-0000-000000000001";
        let now = chrono::Utc::now();

        let session = crate::services::auth::Session {
            id: jti.to_string(),
            user_id: user_id.to_string(),
            token: "dummy".to_string(),
            refresh_token: None,
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            last_accessed: now,
        };

        let session_json = serde_json::to_vec(&session).unwrap();
        let session_data = container.crypto.encrypt_data(&session_json).await.unwrap();

        let entry = secreton_storage::SecretEntry::new(
            format!("sys/auth/sessions/{}", jti),
            session_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            uuid::Uuid::parse_str(user_id).unwrap_or_default(),
        );

        container.storage.store(&entry).await.unwrap();

        let state: AppState = Arc::new(container).into();
        create_router(&config, state)
    }

    async fn get_auth_token(_app: &axum::Router) -> String {
        use jsonwebtoken::{EncodingKey, Header, encode};
        use secreton_auth::jwt::{AccessTokenClaims, Claims};

        let claims = Claims {
            sub: "00000000-0000-0000-0000-000000000001".to_owned(),
            username: "test-user".to_owned(),
            email: Some("test@example.com".to_owned()),
            roles: vec!["admin".to_owned()],
            policies: vec!["admin".to_owned()],
            mfa_required: false,
            iat: 1715638210, // Some fixed time
            exp: 2715638210, // Far future
            iss: "secreton".to_owned(),
            aud: "secreton-api".to_owned(),
            jti: "test-jti".to_owned(),
        };

        let access_claims = AccessTokenClaims {
            claims,
            token_type: "access".to_owned(),
        };

        encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(
                "test_secret_key_for_security_testing_purposes_only".as_ref(),
            ),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_security_headers() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert!(headers.contains_key("x-content-type-options"));
        assert!(headers.contains_key("x-frame-options"));
        assert!(headers.contains_key("x-xss-protection"));
        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("referrer-policy"));
    }

    #[tokio::test]
    async fn test_request_size_limit() {
        let app = setup_test_app().await;
        let token = get_auth_token(&app).await;

        // Create a large body (over 1MB limit)
        let large_body = vec![0u8; 1_100_000];

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/secret/secrets/test")
                    .header("Authorization", format!("Bearer {}", token))
                    .header("Content-Type", "application/json")
                    .header("Content-Length", "1100000")
                    .body(Body::from(large_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be 413 Payload Too Large
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_error_sanitization() {
        let app = setup_test_app().await;
        let token = get_auth_token(&app).await;

        // Trigger a 404 on a valid route prefix to ensure it's handled by our logic
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/secret/secrets/non-existent-secret-path")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        println!("Status: {}, Body: {}", status, body_str);

        // It might be 403 Forbidden if RBAC check fails before resource lookup,
        // or 404 Not Found if RBAC passes but resource is missing.
        // Both are acceptable as long as they return a sanitized JSON response.
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
            "Expected 404 or 403 but got {}. Body: {}",
            status,
            body_str
        );

        // Ensure it's a sanitized JSON response, not a raw error
        assert!(
            body_str.contains("\"success\":false"),
            "Body was: {}",
            body_str
        );
    }
}
