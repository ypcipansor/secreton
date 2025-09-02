#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::models::auth::AuthRequest;

    #[test]
    fn test_kubernetes_config_creation() {
        let config = KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: Some("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string()),
            service_account_token: Some("eyJhbGciOiJSUzI1NiIsImtpZCI6...".to_string()),
            disable_local_ca_jwt: false,
            token_reviewer_jwt: Some("eyJhbGciOiJSUzI1NiIsImtpZCI6...".to_string()),
            issuer: Some("https://kubernetes.default.svc.cluster.local".to_string()),
            audiences: vec!["https://kubernetes.default.svc.cluster.local".to_string()],
            pem_keys: vec!["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string()],
        };

        assert_eq!(config.kubernetes_host, "https://kubernetes.default.svc");
        assert!(config.kubernetes_ca_cert.is_some());
        assert!(!config.disable_local_ca_jwt);
        assert_eq!(config.audiences.len(), 1);
    }

    #[test]
    fn test_kubernetes_role_creation() {
        let role = KubernetesRole {
            name: "test-role".to_string(),
            bound_service_account_names: vec!["default".to_string()],
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

        assert_eq!(role.name, "test-role");
        assert_eq!(role.token_ttl, 3600);
        assert_eq!(role.token_policies.len(), 2);
        assert!(!role.token_no_default_policy);
    }

    #[test]
    fn test_role_matching_service_account() {
        let mut auth = KubernetesAuth::new(KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        });

        let role = KubernetesRole {
            name: "test-role".to_string(),
            bound_service_account_names: vec!["test-sa".to_string()],
            bound_service_account_namespaces: vec!["default".to_string()],
            audience: None,
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

        // Test matching service account
        assert!(auth.role_matches_service_account(
            auth.get_role("test-role").unwrap(),
            "default",
            "test-sa"
        ));

        // Test non-matching service account
        assert!(!auth.role_matches_service_account(
            auth.get_role("test-role").unwrap(),
            "default",
            "other-sa"
        ));

        // Test non-matching namespace
        assert!(!auth.role_matches_service_account(
            auth.get_role("test-role").unwrap(),
            "other-ns",
            "test-sa"
        ));
    }

    #[test]
    fn test_role_management() {
        let mut auth = KubernetesAuth::new(KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        });

        let role = KubernetesRole {
            name: "test-role".to_string(),
            bound_service_account_names: vec![],
            bound_service_account_namespaces: vec![],
            audience: None,
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

        // Test adding role
        auth.add_role("test-role".to_string(), role.clone());
        assert!(auth.get_role("test-role").is_some());

        // Test listing roles
        let roles = auth.list_roles();
        assert_eq!(roles.len(), 1);
        assert!(roles.contains(&"test-role".to_string()));

        // Test removing role
        assert!(auth.remove_role("test-role"));
        assert!(auth.get_role("test-role").is_none());
        assert!(!auth.remove_role("non-existent"));
    }

    #[test]
    fn test_auth_response_creation() {
        let auth = KubernetesAuth::new(KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        });

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
            exp: 1640995200, // 2022-01-01 00:00:00 UTC
            iat: 1640908800, // 2021-12-31 00:00:00 UTC
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

        assert!(response.authenticated);
        assert_eq!(response.user_info.username, "system:serviceaccount:default:test-sa");
        assert_eq!(response.policies, vec!["default".to_string(), "test-policy".to_string()]);
        assert_eq!(response.lease_duration, 3600);
        assert!(response.renewable);
        assert_eq!(response.accessor, "kubernetes-test-uid");
        assert_eq!(response.user_info.metadata.get("service_account_name").unwrap(), "test-sa");
        assert_eq!(response.user_info.metadata.get("service_account_namespace").unwrap(), "default");
    }

    #[test]
    fn test_invalid_auth_request_type() {
        let auth = KubernetesAuth::new(KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        });

        // Test with non-Kubernetes auth request
        let result = tokio_test::block_on(async {
            auth.authenticate(&AuthRequest::Token { token: "test-token".to_string() }).await
        });

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Kubernetes authentication only supports JWT tokens");
    }

    #[test]
    fn test_service_account_validation() {
        let auth = KubernetesAuth::new(KubernetesConfig {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            service_account_token: None,
            disable_local_ca_jwt: false,
            token_reviewer_jwt: None,
            issuer: None,
            audiences: vec![],
            pem_keys: vec![],
        });

        // This would normally make an HTTP request, but for testing we'll just check the method exists
        // In a real test, you'd mock the HTTP client
        let _result = tokio_test::block_on(async {
            auth.validate_service_account("default", "test-sa").await
        });
    }
}
