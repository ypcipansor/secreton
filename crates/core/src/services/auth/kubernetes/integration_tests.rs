#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::collections::HashMap;
    use crate::models::auth::AuthRequest;

    // Mock JWT token for testing (this would normally come from Kubernetes)
    const MOCK_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDp0ZXN0LXNhIiwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjQwOTk1MjAwLCJpYXQiOjE2NDA5MDg4MDAsIm5iZiI6MTY0MDkwODgwMCwianRpIjoidGVzdC1qdGkiLCJrdWJlcm5ldGVzIjp7Im5hbWVzcGFjZSI6ImRlZmF1bHQiLCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoidGVzdC1zYSIsInVpZCI6InRlc3QtdWlkIn19fQ.test-signature";

    #[tokio::test]
    async fn test_kubernetes_auth_integration() {
        let config = KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc.cluster.local:443".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: true, // Use TokenReview API for testing
            token_reviewer_jwt: Some(MOCK_JWT.to_string()),
            issuer: Some("https://kubernetes.default.svc.cluster.local".to_string()),
            audiences: vec!["https://kubernetes.default.svc.cluster.local".to_string()],
            pem_keys: vec![],
        };

        let mut auth = KubernetesAuth::new(config);

        // Create a test role
        let role = KubernetesRole {
            name: "test-role".to_string(),
            bound_service_account_names: vec!["test-sa".to_string()],
            bound_service_account_namespaces: vec!["default".to_string()],
            audience: Some("https://kubernetes.default.svc.cluster.local".to_string()),
            alias_name_source: "serviceaccount_uid".to_string(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            token_policies: vec!["default".to_string(), "test-policy".to_string()],
            token_bound_cidrs: vec![],
            token_explicit_max_ttl: 86400,
            token_no_default_policy: false,
            token_num_uses: 0,
            token_period: 0,
            token_type: "service".to_string(),
        };

        auth.add_role("test-role".to_string(), role);

        // Test authentication request
        let auth_request = AuthRequest::Kubernetes {
            jwt: MOCK_JWT.to_string(),
        };

        // Note: This test would require a mock HTTP server for the TokenReview API
        // For now, we'll test the structure and error handling
        let result = auth.authenticate(&auth_request).await;

        // Since we don't have a real Kubernetes API server, this should fail
        // but it should fail with a network-related error, not a parsing error
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();

        // The error should be related to network/HTTP, not JWT parsing
        assert!(error.contains("TokenReview") || error.contains("http") || error.contains("connect"));
    }

    #[test]
    fn test_role_matching_integration() {
        let config = KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc.cluster.local:443".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        };

        let mut auth = KubernetesAuth::new(config);

        // Create multiple roles for testing
        let role1 = KubernetesRole {
            name: "role1".to_string(),
            bound_service_account_names: vec!["sa1".to_string()],
            bound_service_account_namespaces: vec!["ns1".to_string()],
            audience: None,
            alias_name_source: "serviceaccount_uid".to_string(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            token_policies: vec!["policy1".to_string()],
            token_bound_cidrs: vec![],
            token_explicit_max_ttl: 86400,
            token_no_default_policy: false,
            token_num_uses: 0,
            token_period: 0,
            token_type: "service".to_string(),
        };

        let role2 = KubernetesRole {
            name: "role2".to_string(),
            bound_service_account_names: vec!["sa2".to_string()],
            bound_service_account_namespaces: vec!["ns2".to_string()],
            audience: None,
            alias_name_source: "serviceaccount_uid".to_string(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            token_policies: vec!["policy2".to_string()],
            token_bound_cidrs: vec![],
            token_explicit_max_ttl: 86400,
            token_no_default_policy: false,
            token_num_uses: 0,
            token_period: 0,
            token_type: "service".to_string(),
        };

        auth.add_role("role1".to_string(), role1);
        auth.add_role("role2".to_string(), role2);

        // Test role listing
        let roles = auth.list_roles();
        assert_eq!(roles.len(), 2);
        assert!(roles.contains(&"role1".to_string()));
        assert!(roles.contains(&"role2".to_string()));

        // Test role retrieval
        assert!(auth.get_role("role1").is_some());
        assert!(auth.get_role("role2").is_some());
        assert!(auth.get_role("nonexistent").is_none());

        // Test role removal
        assert!(auth.remove_role("role1"));
        assert!(auth.get_role("role1").is_none());
        assert!(!auth.remove_role("nonexistent"));
    }

    #[test]
    fn test_auth_response_structure() {
        let config = KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc.cluster.local:443".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        };

        let auth = KubernetesAuth::new(config);

        let role = KubernetesRole {
            name: "test-role".to_string(),
            bound_service_account_names: vec![],
            bound_service_account_namespaces: vec![],
            audience: None,
            alias_name_source: "serviceaccount_uid".to_string(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            token_policies: vec!["default".to_string(), "test-policy".to_string()],
            token_bound_cidrs: vec![],
            token_explicit_max_ttl: 86400,
            token_no_default_policy: false,
            token_num_uses: 0,
            token_period: 0,
            token_type: "service".to_string(),
        };

        let claims = KubernetesServiceAccountToken {
            sub: "system:serviceaccount:default:test-sa".to_string(),
            iss: "https://kubernetes.default.svc.cluster.local".to_string(),
            aud: vec!["https://kubernetes.default.svc.cluster.local".to_string()],
            exp: 1640995200,
            iat: 1640908800,
            nbf: None,
            jti: "test-jti".to_string(),
            kubernetes: KubernetesClaims {
                namespace: "default".to_string(),
                serviceaccount: ServiceAccountClaims {
                    name: "test-sa".to_string(),
                    uid: "test-uid".to_string(),
                },
            },
        };

        let response = auth.create_auth_response(&claims, &role).unwrap();

        // Verify response structure
        assert!(response.authenticated);
        assert_eq!(response.user_info.username, "system:serviceaccount:default:test-sa");
        assert_eq!(response.policies.len(), 2);
        assert!(response.policies.contains(&"default".to_string()));
        assert!(response.policies.contains(&"test-policy".to_string()));
        assert_eq!(response.lease_duration, 3600);
        assert!(response.renewable);
        assert_eq!(response.accessor, "kubernetes-test-uid");

        // Verify metadata
        assert_eq!(response.user_info.metadata.get("service_account_name").unwrap(), "test-sa");
        assert_eq!(response.user_info.metadata.get("service_account_namespace").unwrap(), "default");
        assert_eq!(response.user_info.metadata.get("service_account_uid").unwrap(), "test-uid");
    }

    #[test]
    fn test_service_account_username_parsing() {
        let config = KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc.cluster.local:443".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        };

        let auth = KubernetesAuth::new(config);

        // Test valid service account username
        let valid_username = "system:serviceaccount:default:test-sa";
        let parts: Vec<&str> = valid_username.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "system");
        assert_eq!(parts[1], "serviceaccount");
        assert_eq!(parts[2], "default");
        assert_eq!(parts[3], "test-sa");

        // Test invalid service account username
        let invalid_username = "invalid:username";
        let parts: Vec<&str> = invalid_username.split(':').collect();
        assert_ne!(parts.len(), 4);
    }

    #[test]
    fn test_audience_validation() {
        let config = KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc.cluster.local:443".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec!["https://kubernetes.default.svc.cluster.local".to_string()],
            pem_keys: vec![],
        };

        let mut auth = KubernetesAuth::new(config);

        let role = KubernetesRole {
            name: "test-role".to_string(),
            bound_service_account_names: vec!["test-sa".to_string()],
            bound_service_account_namespaces: vec!["default".to_string()],
            audience: Some("https://kubernetes.default.svc.cluster.local".to_string()),
            alias_name_source: "serviceaccount_uid".to_string(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            token_policies: vec!["default".to_string()],
            token_bound_cidrs: vec![],
            token_explicit_max_ttl: 86400,
            token_no_default_policy: false,
            token_num_uses: 0,
            token_period: 0,
            token_type: "service".to_string(),
        };

        auth.add_role("test-role".to_string(), role);

        let claims_with_correct_audience = KubernetesServiceAccountToken {
            sub: "system:serviceaccount:default:test-sa".to_string(),
            iss: "https://kubernetes.default.svc.cluster.local".to_string(),
            aud: vec!["https://kubernetes.default.svc.cluster.local".to_string()],
            exp: 1640995200,
            iat: 1640908800,
            nbf: None,
            jti: "test-jti".to_string(),
            kubernetes: KubernetesClaims {
                namespace: "default".to_string(),
                serviceaccount: ServiceAccountClaims {
                    name: "test-sa".to_string(),
                    uid: "test-uid".to_string(),
                },
            },
        };

        let claims_with_wrong_audience = KubernetesServiceAccountToken {
            sub: "system:serviceaccount:default:test-sa".to_string(),
            iss: "https://kubernetes.default.svc.cluster.local".to_string(),
            aud: vec!["https://wrong.audience.com".to_string()],
            exp: 1640995200,
            iat: 1640908800,
            nbf: None,
            jti: "test-jti".to_string(),
            kubernetes: KubernetesClaims {
                namespace: "default".to_string(),
                serviceaccount: ServiceAccountClaims {
                    name: "test-sa".to_string(),
                    uid: "test-uid".to_string(),
                },
            },
        };

        // Test with correct audience
        assert!(auth.role_matches_claims(
            auth.get_role("test-role").unwrap(),
            &claims_with_correct_audience
        ));

        // Test with wrong audience
        assert!(!auth.role_matches_claims(
            auth.get_role("test-role").unwrap(),
            &claims_with_wrong_audience
        ));
    }
}
