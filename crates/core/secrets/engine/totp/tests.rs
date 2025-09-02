#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage::memory::MemoryStorage;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_engine() -> TotpSecretsEngine {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        TotpSecretsEngine::new(storage).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_totp_key() {
        let mut engine = create_test_engine().await;

        let request = CreateTotpKeyRequest {
            name: "test-key".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: Some("TestIssuer".to_string()),
            account_name: Some("test@example.com".to_string()),
            generate_secret: true,
            secret: None,
        };

        let result = engine.create_key(request).await;
        assert!(result.is_ok(), "Failed to create TOTP key: {:?}", result.err());

        let key = result.unwrap();
        assert_eq!(key.name, "test-key");
        assert_eq!(key.algorithm, "SHA1");
        assert_eq!(key.digits, 6);
        assert_eq!(key.period, 30);
        assert_eq!(key.issuer, Some("TestIssuer".to_string()));
        assert_eq!(key.account_name, Some("test@example.com".to_string()));
        assert!(!key.secret.is_empty());
    }

    #[tokio::test]
    async fn test_create_key_with_custom_secret() {
        let mut engine = create_test_engine().await;

        let request = CreateTotpKeyRequest {
            name: "custom-key".to_string(),
            algorithm: Some("SHA256".to_string()),
            digits: Some(8),
            period: Some(60),
            issuer: None,
            account_name: None,
            generate_secret: false,
            secret: Some("JBSWY3DPEHPK3PXP".to_string()), // Valid base32
        };

        let result = engine.create_key(request).await;
        assert!(result.is_ok(), "Failed to create TOTP key with custom secret: {:?}", result.err());

        let key = result.unwrap();
        assert_eq!(key.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(key.digits, 8);
        assert_eq!(key.period, 60);
    }

    #[tokio::test]
    async fn test_get_key() {
        let mut engine = create_test_engine().await;

        // Create a key first
        let request = CreateTotpKeyRequest {
            name: "get-test".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        engine.create_key(request).await.unwrap();

        // Get the key
        let result = engine.get_key("get-test").await;
        assert!(result.is_ok(), "Failed to get TOTP key: {:?}", result.err());

        let key = result.unwrap();
        assert_eq!(key.name, "get-test");
    }

    #[tokio::test]
    async fn test_list_keys() {
        let mut engine = create_test_engine().await;

        // Create multiple keys
        let keys = vec!["key1", "key2", "key3"];
        for key_name in &keys {
            let request = CreateTotpKeyRequest {
                name: key_name.to_string(),
                algorithm: Some("SHA1".to_string()),
                digits: Some(6),
                period: Some(30),
                issuer: None,
                account_name: None,
                generate_secret: true,
                secret: None,
            };
            engine.create_key(request).await.unwrap();
        }

        let result = engine.list_keys().await;
        assert!(result.is_ok(), "Failed to list TOTP keys: {:?}", result.err());

        let listed_keys = result.unwrap();
        assert_eq!(listed_keys.len(), 3);
        for key_name in &keys {
            assert!(listed_keys.contains(&key_name.to_string()));
        }
    }

    #[tokio::test]
    async fn test_delete_key() {
        let mut engine = create_test_engine().await;

        // Create a key
        let request = CreateTotpKeyRequest {
            name: "delete-test".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        engine.create_key(request).await.unwrap();

        // Verify key exists
        let key = engine.get_key("delete-test").await;
        assert!(key.is_ok());

        // Delete key
        let result = engine.delete_key("delete-test").await;
        assert!(result.is_ok(), "Failed to delete TOTP key: {:?}", result.err());

        // Verify key is gone
        let key = engine.get_key("delete-test").await;
        assert!(key.is_err());
    }

    #[tokio::test]
    async fn test_generate_url() {
        let mut engine = create_test_engine().await;

        // Create a key
        let request = CreateTotpKeyRequest {
            name: "url-test".to_string(),
            algorithm: Some("SHA256".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: Some("TestApp".to_string()),
            account_name: Some("user@test.com".to_string()),
            generate_secret: true,
            secret: None,
        };

        let key = engine.create_key(request).await.unwrap();

        // Generate URL
        let result = engine.generate_url("url-test").await;
        assert!(result.is_ok(), "Failed to generate TOTP URL: {:?}", result.err());

        let totp_url = result.unwrap();
        assert!(totp_url.url.starts_with("otpauth://totp/"));
        assert!(totp_url.url.contains("TestApp"));
        assert!(totp_url.url.contains("user@test.com"));
        assert!(totp_url.url.contains("algorithm=SHA256"));
        assert!(totp_url.url.contains("digits=6"));
        assert!(totp_url.url.contains("period=30"));
    }

    #[tokio::test]
    async fn test_validation_with_known_values() {
        let mut engine = create_test_engine().await;

        // Use a known secret and timestamp for predictable testing
        // RFC 6238 test vector
        let request = CreateTotpKeyRequest {
            name: "rfc-test".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(8),
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: false,
            secret: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()), // RFC test secret
        };

        engine.create_key(request).await.unwrap();

        // Test with RFC 6238 test vector
        // Time: 59 (should produce 94287082)
        let validate_request = ValidateTotpRequest {
            name: "rfc-test".to_string(),
            code: "94287082".to_string(),
            window: Some(0),
        };

        let result = engine.validate_code(validate_request).await;
        assert!(result.is_ok(), "Failed to validate TOTP code: {:?}", result.err());

        let validation = result.unwrap();
        assert!(validation.valid, "Expected code to be valid");
        assert_eq!(validation.key_name, "rfc-test");
    }

    #[tokio::test]
    async fn test_invalid_code() {
        let mut engine = create_test_engine().await;

        // Create a key
        let request = CreateTotpKeyRequest {
            name: "invalid-test".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        engine.create_key(request).await.unwrap();

        // Try to validate with invalid code
        let validate_request = ValidateTotpRequest {
            name: "invalid-test".to_string(),
            code: "000000".to_string(), // Invalid code
            window: Some(0),
        };

        let result = engine.validate_code(validate_request).await;
        assert!(result.is_ok(), "Failed to validate TOTP code: {:?}", result.err());

        let validation = result.unwrap();
        assert!(!validation.valid, "Expected code to be invalid");
    }

    #[tokio::test]
    async fn test_validation_window() {
        let mut engine = create_test_engine().await;

        // Create a key
        let request = CreateTotpKeyRequest {
            name: "window-test".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        engine.create_key(request).await.unwrap();

        // Get current time and generate a valid code
        let now = Utc::now().timestamp() as u64;
        let key = engine.get_key("window-test").await.unwrap();
        let valid_code = engine.generate_totp(&key, now).await.unwrap();

        // Test with window of 2 (should check ±2 time steps)
        let validate_request = ValidateTotpRequest {
            name: "window-test".to_string(),
            code: valid_code,
            window: Some(2),
        };

        let result = engine.validate_code(validate_request).await;
        assert!(result.is_ok(), "Failed to validate TOTP code: {:?}", result.err());

        let validation = result.unwrap();
        assert!(validation.valid, "Expected code to be valid within window");
        assert!(validation.window_used.is_some(), "Expected window to be used");
    }

    #[tokio::test]
    async fn test_key_validation() {
        let mut engine = create_test_engine().await;

        // Test invalid algorithm
        let request = CreateTotpKeyRequest {
            name: "invalid-algo".to_string(),
            algorithm: Some("INVALID".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        let result = engine.create_key(request).await;
        assert!(result.is_err(), "Expected error for invalid algorithm");

        // Test invalid digits
        let request = CreateTotpKeyRequest {
            name: "invalid-digits".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(10), // Invalid
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        let result = engine.create_key(request).await;
        assert!(result.is_err(), "Expected error for invalid digits");

        // Test invalid period
        let request = CreateTotpKeyRequest {
            name: "invalid-period".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(6),
            period: Some(500), // Too high
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        let result = engine.create_key(request).await;
        assert!(result.is_err(), "Expected error for invalid period");
    }

    #[tokio::test]
    async fn test_usage_statistics() {
        let mut engine = create_test_engine().await;

        // Create a key
        let request = CreateTotpKeyRequest {
            name: "stats-test".to_string(),
            algorithm: Some("SHA1".to_string()),
            digits: Some(6),
            period: Some(30),
            issuer: None,
            account_name: None,
            generate_secret: true,
            secret: None,
        };

        engine.create_key(request).await.unwrap();

        // Get initial key
        let initial_key = engine.get_key("stats-test").await.unwrap();
        assert_eq!(initial_key.usage_count, 0);
        assert!(initial_key.last_used.is_none());

        // Generate a valid code and validate it
        let now = Utc::now().timestamp() as u64;
        let key = engine.get_key("stats-test").await.unwrap();
        let valid_code = engine.generate_totp(&key, now).await.unwrap();

        let validate_request = ValidateTotpRequest {
            name: "stats-test".to_string(),
            code: valid_code,
            window: Some(0),
        };

        engine.validate_code(validate_request).await.unwrap();

        // Check updated statistics
        let updated_key = engine.get_key("stats-test").await.unwrap();
        assert_eq!(updated_key.usage_count, 1);
        assert!(updated_key.last_used.is_some());
    }
}
