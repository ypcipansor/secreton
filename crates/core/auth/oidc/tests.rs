// OIDC Authentication Tests
// Comprehensive test suite for OpenID Connect authentication

#[cfg(test)]
mod tests {
    // Import from parent module scope
    use super::super::{OidcAuth, OidcConfig, OidcCredentials, OidcUser};
    use super::super::super::traits::{AuthMethod, Credentials};
    use super::super::validator::{JwtClaims, UserInfo};
    use crate::storage::in_memory::InMemoryStorage;
    use crate::audit::AuditLogger;
    use std::sync::Arc;
    use std::collections::HashMap;
    use tokio;
    use serde_json::json;
    use chrono::Utc;

    // Mock HTTP server for testing OIDC endpoints
    use std::sync::atomic::{AtomicU16, Ordering};
    use tokio::net::TcpListener;
    use axum::{
        response::Json,
        routing::get,
        Router,
    };

    static PORT: AtomicU16 = AtomicU16::new(3000);

    async fn start_mock_oidc_server() -> u16 {
        let port = PORT.fetch_add(1, Ordering::SeqCst);
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await.unwrap();
        
        let app = Router::new()
            .route("/.well-known/openid_configuration", get(discovery_endpoint))
            .route("/jwks", get(jwks_endpoint));

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        port
    }

    async fn discovery_endpoint() -> Json<serde_json::Value> {
        Json(json!({
            "issuer": "https://example.auth0.com/",
            "authorization_endpoint": "https://example.auth0.com/authorize",
            "token_endpoint": "https://example.auth0.com/oauth/token",
            "userinfo_endpoint": "https://example.auth0.com/userinfo",
            "jwks_uri": "https://example.auth0.com/jwks",
            "scopes_supported": ["openid", "profile", "email"],
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "claims_supported": ["sub", "email", "name", "groups"]
        }))
    }

    async fn jwks_endpoint() -> Json<serde_json::Value> {
        Json(json!({
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key-1",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        }))
    }

    fn create_test_config() -> OidcConfig {
        OidcConfig {
            provider_name: "test_provider".to_string(),
            discovery_url: url::Url::parse("http://127.0.0.1:3000/.well-known/openid_configuration").unwrap(),
            client_id: "test_client_id".to_string(),
            client_secret: Some("test_client_secret".to_string()),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            claims_mapping: Default::default(),
            jwt_validation: Default::default(),
            user_provisioning: Default::default(),
            cache_settings: Default::default(),
            provider_settings: HashMap::new(),
        }
    }

    async fn create_test_oidc_auth() -> OidcAuth {
        let config = create_test_config();
        let storage = Arc::new(InMemoryStorage::new());
        let audit_logger = AuditLogger::new(vec![]);
        OidcAuth::new(config, storage, audit_logger).unwrap()
    }

    // Test JWT token creation for testing
    fn create_test_jwt() -> String {
        use jsonwebtoken::{encode, Header, EncodingKey};
        use validator::JwtClaims;
        use std::time::{SystemTime, UNIX_EPOCH};

        let claims = JwtClaims {
            iss: "https://example.auth0.com/".to_string(),
            sub: "auth0|123456789".to_string(),
            aud: serde_json::Value::String("test_client_id".to_string()),
            exp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
            iat: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            nbf: None,
            jti: Some("test-jti".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            preferred_username: Some("testuser".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
            locale: Some("en".to_string()),
            custom_claims: {
                let mut claims = HashMap::new();
                claims.insert("groups".to_string(), serde_json::Value::Array(vec![
                    serde_json::Value::String("admin".to_string()),
                    serde_json::Value::String("users".to_string()),
                ]));
                claims.insert("role".to_string(), serde_json::Value::String("manager".to_string()));
                claims
            },
        };

        // Use a test RSA key (in real implementation, this would come from JWKS)
        let key = EncodingKey::from_secret("test_secret".as_ref());
        encode(&Header::default(), &claims, &key).unwrap()
    }

    #[tokio::test]
    async fn test_oidc_auth_creation() {
        let oidc_auth = create_test_oidc_auth().await;
        assert_eq!(oidc_auth.get_config().provider_name, "test_provider");
        assert_eq!(oidc_auth.get_config().client_id, "test_client_id");
    }

    #[tokio::test]
    async fn test_config_validation() {
        let mut config = create_test_config();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid config - empty client_id
        config.client_id.clear();
        assert!(config.validate().is_err());
        
        // Invalid config - missing openid scope
        config.client_id = "test".to_string();
        config.scopes.clear();
        config.scopes.push("profile".to_string());
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_auth0_config_factory() {
        let config = OidcConfig::auth0("example.auth0.com", "client123", Some("secret")).unwrap();
        
        assert_eq!(config.provider_name, "auth0");
        assert_eq!(config.client_id, "client123");
        assert_eq!(config.client_secret, Some("secret".to_string()));
        assert!(config.discovery_url.as_str().contains("example.auth0.com"));
        assert_eq!(config.claims_mapping.username_claim, "nickname");
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_okta_config_factory() {
        let config = OidcConfig::okta("dev-123.okta.com", "client456", None).unwrap();
        
        assert_eq!(config.provider_name, "okta");
        assert_eq!(config.client_id, "client456");
        assert_eq!(config.client_secret, None);
        assert!(config.discovery_url.as_str().contains("dev-123.okta.com"));
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_azure_ad_config_factory() {
        let config = OidcConfig::azure_ad("tenant-123", "app-456", Some("secret")).unwrap();
        
        assert_eq!(config.provider_name, "azure_ad");
        assert_eq!(config.client_id, "app-456");
        assert!(config.discovery_url.as_str().contains("tenant-123"));
        assert!(config.jwt_validation.audiences.contains(&"app-456".to_string()));
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_oidc_credentials_creation() {
        let token = create_test_jwt();
        let context = HashMap::new();
        
        let credentials = OidcCredentials {
            jwt_token: token.clone(),
            provider: Some("test_provider".to_string()),
            context,
        };
        
        assert_eq!(credentials.jwt_token, token);
        assert_eq!(credentials.provider, Some("test_provider".to_string()));
    }

    #[tokio::test]
    async fn test_credentials_enum_oidc() {
        let token = create_test_jwt();
        let mut context = HashMap::new();
        context.insert("origin".to_string(), "test".to_string());
        
        let credentials = Credentials::Oidc {
            jwt_token: token.clone(),
            provider: Some("test_provider".to_string()),
            context: context.clone(),
        };
        
        match credentials {
            Credentials::Oidc { jwt_token, provider, context: ctx } => {
                assert_eq!(jwt_token, token);
                assert_eq!(provider, Some("test_provider".to_string()));
                assert_eq!(ctx.get("origin"), Some(&"test".to_string()));
            },
            _ => panic!("Expected OIDC credentials"),
        }
    }

    #[tokio::test]
    async fn test_user_policy_calculation() {
        let mut config = create_test_config();
        config.claims_mapping.default_policies = vec!["default".to_string()];
        config.claims_mapping.group_policies.insert("admin".to_string(), vec!["admin_policy".to_string()]);
        config.claims_mapping.role_policies.insert("manager".to_string(), vec!["manager_policy".to_string()]);
        
        let storage = Arc::new(InMemoryStorage::new());
        let audit_logger = AuditLogger::new(vec![]);
        let oidc_auth = OidcAuth::new(config, storage, audit_logger).unwrap();
        
        let user_info = UserInfo {
            user_id: "auth0|123456789".to_string(),
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            groups: vec!["admin".to_string()],
            roles: vec!["manager".to_string()],
            metadata: HashMap::new(),
            claims: JwtClaims {
                iss: "test".to_string(),
                sub: "auth0|123456789".to_string(),
                aud: serde_json::Value::String("client".to_string()),
                exp: 1234567890,
                iat: 1234567890,
                nbf: None,
                jti: None,
                email: Some("test@example.com".to_string()),
                email_verified: None,
                name: None,
                given_name: None,
                family_name: None,
                preferred_username: None,
                picture: None,
                locale: None,
                custom_claims: HashMap::new(),
            },
        };
        
        let policies = oidc_auth.calculate_user_policies(&user_info);
        assert!(policies.contains(&"default".to_string()));
        assert!(policies.contains(&"admin_policy".to_string()));
        assert!(policies.contains(&"manager_policy".to_string()));
        assert_eq!(policies.len(), 3);
    }

    #[tokio::test]
    async fn test_auth_method_interface() {
        let oidc_auth = create_test_oidc_auth().await;
        
        // Test method name and description
        assert_eq!(oidc_auth.name(), "oidc");
        assert!(oidc_auth.description().contains("OpenID Connect"));
        assert!(oidc_auth.supports_user_management());
        assert!(!oidc_auth.supports_mfa()); // MFA is handled by external provider
    }

    #[tokio::test]
    async fn test_config_validation_interface() {
        let oidc_auth = create_test_oidc_auth().await;
        
        // Valid config
        let valid_config = serde_json::to_value(create_test_config()).unwrap();
        assert!(oidc_auth.validate_config(&valid_config).await.is_ok());
        
        // Invalid config
        let invalid_config = json!({"invalid": "config"});
        assert!(oidc_auth.validate_config(&invalid_config).await.is_err());
    }

    #[tokio::test]
    async fn test_user_management_interface() {
        let oidc_auth = create_test_oidc_auth().await;
        
        // List users (should be empty initially)
        let users = oidc_auth.list_users().await.unwrap();
        assert!(users.is_empty());
        
        // Create user should fail (OIDC users are auto-created)
        let result = oidc_auth.create_user("testuser", &json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("automatically created"));
        
        // Delete non-existent user should fail
        let result = oidc_auth.delete_user("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_provider_stats() {
        let oidc_auth = create_test_oidc_auth().await;
        
        let stats = oidc_auth.get_provider_stats().await.unwrap();
        assert_eq!(stats.provider_name, "test_provider");
        assert_eq!(stats.client_id, "test_client_id");
        assert_eq!(stats.user_count, 0);
        assert_eq!(stats.cached_users, 0);
    }

    #[tokio::test]
    async fn test_cache_management() {
        let oidc_auth = create_test_oidc_auth().await;
        
        // Test that user cache is initially empty
        assert!(oidc_auth.get_cached_user("nonexistent").await.unwrap().is_none());
        
        // Cache cleanup should work without errors
        let user = User {
            id: 1,
            username: "testuser".to_string(),
            password_hash: "hash".to_string(),
            created_at: Utc::now(),
            namespace: "default".to_string(),
        };
        
        let user_info = UserInfo {
            user_id: "test-user-id".to_string(),
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            groups: vec![],
            roles: vec![],
            metadata: HashMap::new(),
            claims: JwtClaims {
                iss: "test".to_string(),
                sub: "test-user-id".to_string(),
                aud: serde_json::Value::String("client".to_string()),
                exp: 1234567890,
                iat: 1234567890,
                nbf: None,
                jti: None,
                email: Some("test@example.com".to_string()),
                email_verified: None,
                name: None,
                given_name: None,
                family_name: None,
                preferred_username: None,
                picture: None,
                locale: None,
                custom_claims: HashMap::new(),
            },
        };
        
        // Cache user
        assert!(oidc_auth.cache_user(&user, &user_info).await.is_ok());
        
        // Should be able to retrieve cached user
        let cached = oidc_auth.get_cached_user("test-user-id").await.unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().user.username, "testuser");
    }

    #[tokio::test]
    async fn test_multiple_providers() {
        // Test Auth0 configuration
        let auth0_config = OidcConfig::auth0("example.auth0.com", "auth0_client", Some("secret")).unwrap();
        let storage1 = Arc::new(InMemoryStorage::new());
        let audit_logger1 = AuditLogger::new(vec![]);
        let auth0_auth = OidcAuth::new(auth0_config, storage1, audit_logger1).unwrap();
        
        // Test Okta configuration
        let okta_config = OidcConfig::okta("dev-123.okta.com", "okta_client", None).unwrap();
        let storage2 = Arc::new(InMemoryStorage::new());
        let audit_logger2 = AuditLogger::new(vec![]);
        let okta_auth = OidcAuth::new(okta_config, storage2, audit_logger2).unwrap();
        
        // Test Azure AD configuration
        let azure_config = OidcConfig::azure_ad("tenant-123", "azure_client", Some("secret")).unwrap();
        let storage3 = Arc::new(InMemoryStorage::new());
        let audit_logger3 = AuditLogger::new(vec![]);
        let azure_auth = OidcAuth::new(azure_config, storage3, audit_logger3).unwrap();
        
        // Verify each provider has correct configuration
        assert_eq!(auth0_auth.get_config().provider_name, "auth0");
        assert_eq!(okta_auth.get_config().provider_name, "okta");
        assert_eq!(azure_auth.get_config().provider_name, "azure_ad");
        
        // Verify provider-specific settings
        assert_eq!(auth0_auth.get_config().claims_mapping.username_claim, "nickname");
        assert_eq!(okta_auth.get_config().claims_mapping.username_claim, "preferred_username");
        assert_eq!(azure_auth.get_config().claims_mapping.username_claim, "unique_name");
    }

    #[tokio::test]
    async fn test_error_handling() {
        let oidc_auth = create_test_oidc_auth().await;
        
        // Test invalid credentials type
        let invalid_creds = Credentials::Password {
            username: "test".to_string(),
            password: "test".to_string(),
        };
        
        let result = oidc_auth.authenticate(&invalid_creds).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OIDC authentication requires"));
        
        // Test invalid Generic credentials
        let invalid_generic = Credentials::Generic(json!({"invalid": "format"}));
        let result = oidc_auth.authenticate(&invalid_generic).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid OIDC credentials format"));
    }

    #[tokio::test]
    async fn test_config_update() {
        let mut oidc_auth = create_test_oidc_auth().await;
        
        // Create new config
        let mut new_config = create_test_config();
        new_config.provider_name = "updated_provider".to_string();
        new_config.client_id = "new_client_id".to_string();
        
        // Update configuration
        assert!(oidc_auth.update_config(new_config).await.is_ok());
        
        // Verify update
        assert_eq!(oidc_auth.get_config().provider_name, "updated_provider");
        assert_eq!(oidc_auth.get_config().client_id, "new_client_id");
        
        // Test invalid config update
        let mut invalid_config = create_test_config();
        invalid_config.client_id.clear(); // Invalid
        
        let result = oidc_auth.update_config(invalid_config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_providers() {
        let oidc_auth = create_test_oidc_auth().await;
        
        let providers = oidc_auth.list_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0], "test_provider");
    }
}
