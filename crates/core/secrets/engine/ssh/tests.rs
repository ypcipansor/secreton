#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage::memory::MemoryStorage;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_engine() -> SshSecretsEngine {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        SshSecretsEngine::new(storage).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_ca() {
        let mut engine = create_test_engine().await;

        let ca_config = CreateCaRequest {
            ca_type: "user".to_string(),
            key_type: "rsa".to_string(),
            key_bits: 2048,
            max_ttl: 86400,
            default_ttl: 3600,
            allow_user_certificates: true,
            allow_host_certificates: false,
            allowed_users: Some(vec!["*".to_string()]),
            allowed_domains: None,
            default_extensions: None,
            key_id_format: None,
        };

        let result = engine.create_ca(ca_config).await;
        assert!(result.is_ok(), "Failed to create CA: {:?}", result.err());

        // Verify CA was created
        let ca_data = engine.get_ca("user").await;
        assert!(ca_data.is_ok(), "Failed to retrieve CA: {:?}", ca_data.err());
    }

    #[tokio::test]
    async fn test_generate_keypair() {
        let engine = create_test_engine().await;

        let result = engine.generate_keypair("rsa", 2048).await;
        assert!(result.is_ok(), "Failed to generate keypair: {:?}", result.err());

        let key_pair = result.unwrap();
        assert!(key_pair.private_key.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(key_pair.public_key.starts_with("ssh-rsa"));
        assert!(key_pair.fingerprint.contains("SHA256:"));
    }

    #[tokio::test]
    async fn test_create_role() {
        let mut engine = create_test_engine().await;

        let role_config = SshRole {
            name: "test-role".to_string(),
            ca_type: "user".to_string(),
            allowed_users: vec!["user1".to_string(), "user2".to_string()],
            allowed_domains: Some(vec!["example.com".to_string()]),
            key_type: "rsa".to_string(),
            key_bits: 2048,
            max_ttl: 86400,
            default_ttl: 3600,
            allow_user_certificates: true,
            allow_host_certificates: false,
            default_extensions: Some(HashMap::from([
                ("permit-X11-forwarding".to_string(), "".to_string()),
                ("permit-agent-forwarding".to_string(), "".to_string()),
            ])),
            key_id_format: Some("{{token_display_name}}".to_string()),
        };

        let result = engine.create_role(role_config).await;
        assert!(result.is_ok(), "Failed to create role: {:?}", result.err());

        // Verify role was created
        let role_data = engine.get_role("test-role").await;
        assert!(role_data.is_ok(), "Failed to retrieve role: {:?}", role_data.err());
    }

    #[tokio::test]
    async fn test_list_roles() {
        let mut engine = create_test_engine().await;

        // Create multiple roles
        let role1 = SshRole {
            name: "role1".to_string(),
            ca_type: "user".to_string(),
            allowed_users: vec!["user1".to_string()],
            allowed_domains: None,
            key_type: "rsa".to_string(),
            key_bits: 2048,
            max_ttl: 3600,
            default_ttl: 1800,
            allow_user_certificates: true,
            allow_host_certificates: false,
            default_extensions: None,
            key_id_format: None,
        };

        let role2 = SshRole {
            name: "role2".to_string(),
            ca_type: "host".to_string(),
            allowed_users: vec!["*".to_string()],
            allowed_domains: Some(vec!["*.example.com".to_string()]),
            key_type: "ecdsa".to_string(),
            key_bits: 256,
            max_ttl: 7200,
            default_ttl: 3600,
            allow_user_certificates: false,
            allow_host_certificates: true,
            default_extensions: None,
            key_id_format: None,
        };

        engine.create_role(role1).await.unwrap();
        engine.create_role(role2).await.unwrap();

        let roles = engine.list_roles().await.unwrap();
        assert_eq!(roles.len(), 2);
        assert!(roles.contains(&"role1".to_string()));
        assert!(roles.contains(&"role2".to_string()));
    }

    #[tokio::test]
    async fn test_delete_role() {
        let mut engine = create_test_engine().await;

        let role_config = SshRole {
            name: "delete-test".to_string(),
            ca_type: "user".to_string(),
            allowed_users: vec!["testuser".to_string()],
            allowed_domains: None,
            key_type: "rsa".to_string(),
            key_bits: 2048,
            max_ttl: 3600,
            default_ttl: 1800,
            allow_user_certificates: true,
            allow_host_certificates: false,
            default_extensions: None,
            key_id_format: None,
        };

        engine.create_role(role_config).await.unwrap();

        // Verify role exists
        let role_data = engine.get_role("delete-test").await;
        assert!(role_data.is_ok());

        // Delete role
        let result = engine.delete_role("delete-test").await;
        assert!(result.is_ok(), "Failed to delete role: {:?}", result.err());

        // Verify role is gone
        let role_data = engine.get_role("delete-test").await;
        assert!(role_data.is_err());
    }

    #[tokio::test]
    async fn test_ca_operations() {
        let mut engine = create_test_engine().await;

        // Create user CA
        let user_ca_config = CreateCaRequest {
            ca_type: "user".to_string(),
            key_type: "rsa".to_string(),
            key_bits: 2048,
            max_ttl: 86400,
            default_ttl: 3600,
            allow_user_certificates: true,
            allow_host_certificates: false,
            allowed_users: Some(vec!["*".to_string()]),
            allowed_domains: None,
            default_extensions: None,
            key_id_format: None,
        };

        engine.create_ca(user_ca_config).await.unwrap();

        // Create host CA
        let host_ca_config = CreateCaRequest {
            ca_type: "host".to_string(),
            key_type: "ecdsa".to_string(),
            key_bits: 256,
            max_ttl: 172800,
            default_ttl: 7200,
            allow_user_certificates: false,
            allow_host_certificates: true,
            allowed_users: None,
            allowed_domains: Some(vec!["*.company.com".to_string()]),
            default_extensions: None,
            key_id_format: None,
        };

        engine.create_ca(host_ca_config).await.unwrap();

        // List CAs
        let cas = engine.list_cas().await.unwrap();
        assert_eq!(cas.len(), 2);
        assert!(cas.contains(&"user".to_string()));
        assert!(cas.contains(&"host".to_string()));

        // Get specific CA
        let user_ca = engine.get_ca("user").await.unwrap();
        assert_eq!(user_ca.ca_type, "user");
        assert!(user_ca.public_key.starts_with("ssh-rsa"));

        let host_ca = engine.get_ca("host").await.unwrap();
        assert_eq!(host_ca.ca_type, "host");
        assert!(host_ca.public_key.starts_with("ecdsa-sha2-nistp256"));
    }
}
