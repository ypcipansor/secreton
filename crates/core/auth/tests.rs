// Comprehensive tests for all authentication methods

#[cfg(test)]
mod github_auth_tests {
    use crate::auth::github::{GitHubAuth, GitHubAuthConfig};
    use crate::auth::traits::AuthMethod;
    use std::collections::HashMap;

    #[test]
    fn test_github_auth_creation() {
        let config = GitHubAuthConfig::default();
        let auth = GitHubAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_github_auth_method_type() {
        let config = GitHubAuthConfig::default();
        let auth = GitHubAuth::new(config).unwrap();
        assert_eq!(auth.method_type(), "github");
    }

    #[test]
    fn test_github_config_with_organization() {
        let mut config = GitHubAuthConfig::default();
        config.organization = "my-org".to_string();
        config.allowed_teams = vec!["team1".to_string(), "team2".to_string()];
        
        let auth = GitHubAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_github_team_restrictions() {
        let mut config = GitHubAuthConfig::default();
        config.allowed_teams = vec!["engineering".to_string(), "devops".to_string()];
        let auth = GitHubAuth::new(config).unwrap();
        
        assert!(auth.is_team_allowed(&["engineering".to_string()]));
        assert!(auth.is_team_allowed(&["devops".to_string()]));
        assert!(!auth.is_team_allowed(&["marketing".to_string()]));
    }

    #[test]
    fn test_github_no_team_restrictions() {
        let config = GitHubAuthConfig::default();
        let auth = GitHubAuth::new(config).unwrap();
        
        // Should allow any team when no restrictions
        assert!(auth.is_team_allowed(&["any-team".to_string()]));
    }

    #[tokio::test]
    async fn test_github_auth_missing_token() {
        let config = GitHubAuthConfig::default();
        let auth = GitHubAuth::new(config).unwrap();
        
        let credentials = HashMap::new();
        let result = auth.authenticate(credentials).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod jwt_auth_tests {
    use crate::auth::jwt::{JwtAuth, JwtAuthConfig};
    use crate::auth::traits::AuthMethod;
    use std::collections::HashMap;

    #[test]
    fn test_jwt_auth_creation_with_secret() {
        let mut config = JwtAuthConfig::default();
        config.secret_key = Some("test-secret-key".to_string());
        
        let auth = JwtAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_jwt_auth_creation_without_keys() {
        let config = JwtAuthConfig::default();
        let auth = JwtAuth::new(config);
        assert!(auth.is_err());
    }

    #[test]
    fn test_jwt_auth_method_type() {
        let mut config = JwtAuthConfig::default();
        config.secret_key = Some("test-secret".to_string());
        let auth = JwtAuth::new(config).unwrap();
        assert_eq!(auth.method_type(), "jwt");
    }

    #[test]
    fn test_jwt_config_algorithms() {
        let algorithms = vec!["HS256", "HS384", "HS512"];
        
        for algo in algorithms {
            let mut config = JwtAuthConfig::default();
            config.algorithm = algo.to_string();
            config.secret_key = Some("test-secret".to_string());
            
            let auth = JwtAuth::new(config);
            assert!(auth.is_ok(), "Algorithm {} should be supported", algo);
        }
    }

    #[test]
    fn test_jwt_config_with_issuer_and_audience() {
        let mut config = JwtAuthConfig::default();
        config.secret_key = Some("test-secret".to_string());
        config.issuer = Some("https://issuer.example.com".to_string());
        config.audience = Some("my-app".to_string());
        
        let auth = JwtAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_jwt_required_claims() {
        let mut config = JwtAuthConfig::default();
        config.secret_key = Some("test-secret".to_string());
        config.required_claims = vec!["sub".to_string(), "email".to_string()];
        
        let auth = JwtAuth::new(config);
        assert!(auth.is_ok());
    }

    #[tokio::test]
    async fn test_jwt_auth_missing_token() {
        let mut config = JwtAuthConfig::default();
        config.secret_key = Some("test-secret".to_string());
        let auth = JwtAuth::new(config).unwrap();
        
        let credentials = HashMap::new();
        let result = auth.authenticate(credentials).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod kubernetes_auth_tests {
    use crate::auth::kubernetes::{KubernetesAuth, KubernetesAuthConfig, ServiceAccountInfo};
    use crate::auth::traits::AuthMethod;
    use std::collections::HashMap;

    #[test]
    fn test_kubernetes_auth_creation() {
        let config = KubernetesAuthConfig::default();
        let auth = KubernetesAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_kubernetes_auth_method_type() {
        let config = KubernetesAuthConfig::default();
        let auth = KubernetesAuth::new(config).unwrap();
        assert_eq!(auth.method_type(), "kubernetes");
    }

    #[test]
    fn test_kubernetes_config_with_host() {
        let mut config = KubernetesAuthConfig::default();
        config.kubernetes_host = "https://k8s.example.com".to_string();
        
        let auth = KubernetesAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_kubernetes_namespace_restrictions() {
        let mut config = KubernetesAuthConfig::default();
        config.allowed_namespaces = vec!["production".to_string(), "staging".to_string()];
        let auth = KubernetesAuth::new(config).unwrap();
        
        let sa_prod = ServiceAccountInfo {
            name: "app".to_string(),
            namespace: "production".to_string(),
            uid: "uid-1".to_string(),
        };
        assert!(auth.is_allowed(&sa_prod));
        
        let sa_dev = ServiceAccountInfo {
            name: "app".to_string(),
            namespace: "development".to_string(),
            uid: "uid-2".to_string(),
        };
        assert!(!auth.is_allowed(&sa_dev));
    }

    #[test]
    fn test_kubernetes_service_account_restrictions() {
        let mut config = KubernetesAuthConfig::default();
        config.allowed_service_accounts = vec!["vault-auth".to_string()];
        let auth = KubernetesAuth::new(config).unwrap();
        
        let sa_allowed = ServiceAccountInfo {
            name: "vault-auth".to_string(),
            namespace: "default".to_string(),
            uid: "uid-1".to_string(),
        };
        assert!(auth.is_allowed(&sa_allowed));
        
        let sa_denied = ServiceAccountInfo {
            name: "other-sa".to_string(),
            namespace: "default".to_string(),
            uid: "uid-2".to_string(),
        };
        assert!(!auth.is_allowed(&sa_denied));
    }

    #[test]
    fn test_kubernetes_no_restrictions() {
        let config = KubernetesAuthConfig::default();
        let auth = KubernetesAuth::new(config).unwrap();
        
        let sa = ServiceAccountInfo {
            name: "any-sa".to_string(),
            namespace: "any-namespace".to_string(),
            uid: "any-uid".to_string(),
        };
        assert!(auth.is_allowed(&sa));
    }

    #[tokio::test]
    async fn test_kubernetes_auth_missing_token() {
        let config = KubernetesAuthConfig::default();
        let auth = KubernetesAuth::new(config).unwrap();
        
        let credentials = HashMap::new();
        let result = auth.authenticate(credentials).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod auth_integration_tests {
    use crate::auth::traits::AuthResult;

    #[test]
    fn test_auth_result_creation() {
        let result = AuthResult {
            authenticated: true,
            user_id: "user123".to_string(),
            username: "testuser".to_string(),
            policies: vec!["policy1".to_string(), "policy2".to_string()],
            metadata: std::collections::HashMap::new(),
            ttl: 3600,
        };
        
        assert!(result.authenticated);
        assert_eq!(result.user_id, "user123");
        assert_eq!(result.policies.len(), 2);
        assert_eq!(result.ttl, 3600);
    }

    #[test]
    fn test_auth_result_with_metadata() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("role".to_string(), "admin".to_string());
        metadata.insert("department".to_string(), "engineering".to_string());
        
        let result = AuthResult {
            authenticated: true,
            user_id: "user123".to_string(),
            username: "testuser".to_string(),
            policies: vec!["admin".to_string()],
            metadata: metadata.clone(),
            ttl: 7200,
        };
        
        assert_eq!(result.metadata.len(), 2);
        assert_eq!(result.metadata.get("role"), Some(&"admin".to_string()));
    }
}
