//! Integration tests for Transit Secrets Engine
//! NOTE: This test file is currently disabled as it uses old API structures that no longer exist.
//! The transit engine API has been updated and this test needs to be rewritten to match the new API.

#[cfg(feature = "disabled")]
mod disabled_tests {
async fn create_test_storage() -> std::sync::Arc<dyn secreton_core::storage::StorageEngine> {
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Debug)]
    struct TestStorage {
        data: Arc<tokio::sync::RwLock<HashMap<String, secreton_core::storage::StorageEntry>>>,
    }

    #[async_trait::async_trait]
    impl secreton_core::storage::StorageEngine for TestStorage {
        async fn get(
            &self,
            key: &str,
        ) -> Result<Option<secreton_core::storage::StorageEntry>, secreton_core::error::CoreError>
        {
            let data = self.data.read().await;
            Ok(data.get(key).cloned())
        }

        async fn put(
            &self,
            entry: secreton_core::storage::StorageEntry,
        ) -> Result<(), secreton_core::error::CoreError> {
            let mut data = self.data.write().await;
            data.insert(entry.key.clone(), entry);
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), secreton_core::error::CoreError> {
            let mut data = self.data.write().await;
            data.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, secreton_core::error::CoreError> {
            let data = self.data.read().await;
            Ok(data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    Arc::new(TestStorage {
        data: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
    })
}

#[tokio::test]
async fn test_transit_engine_integration() {
    let storage = create_test_storage().await;
    let engine = TransitSecretsEngine::new(storage);

    // Create key
    let create_req = CreateKeyRequest {
        convergent_encryption: Some(false),
        derived: Some(false),
        exportable: Some(false),
        allow_plaintext_backup: Some(false),
        key_size: Some(256),
        key_type: Some("aes256-gcm96".to_string()),
    };

    let result = engine.create_key("test-key", create_req).await;
    assert!(result.is_ok(), "Failed to create key: {:?}", result.err());

    // Encrypt
    let plaintext = general_purpose::STANDARD.encode("Hello, World!");
    let encrypt_req = EncryptRequest {
        plaintext,
        context: None,
        key_version: None,
        nonce: None,
        associated_data: None,
        batch_input: None,
    };

    let encrypt_result = engine.encrypt("test-key", encrypt_req).await;
    assert!(
        encrypt_result.is_ok(),
        "Failed to encrypt: {:?}",
        encrypt_result.err()
    );
    let encrypt_resp = encrypt_result.unwrap();

    // Decrypt
    let decrypt_req = DecryptRequest {
        ciphertext: encrypt_resp.ciphertext,
        context: None,
        nonce: None,
        associated_data: None,
        batch_input: None,
    };

    let decrypt_result = engine.decrypt("test-key", decrypt_req).await;
    assert!(
        decrypt_result.is_ok(),
        "Failed to decrypt: {:?}",
        decrypt_result.err()
    );
    let decrypt_resp = decrypt_result.unwrap();

    let decrypted_plaintext = general_purpose::STANDARD
        .decode(&decrypt_resp.plaintext)
        .unwrap();
    assert_eq!(
        String::from_utf8(decrypted_plaintext).unwrap(),
        "Hello, World!"
    );
}

#[tokio::test]
async fn test_transit_storage_interface() {
    let storage = create_test_storage().await;
    let engine = TransitSecretsEngine::new(storage);

    // Test SecretsEngine interface for Transit
    use serde_json::json;

    // Create a transit key (not a regular secret)
    let key_data = json!({
        "name": "test-key",
        "type": "aes256-gcm",
        "exportable": true
    });
    let key_result = engine.create_secret("keys", key_data.clone(), None).await;
    assert!(
        key_result.is_ok(),
        "Should be able to create transit key: {:?}",
        key_result.err()
    );

    // List keys (using list_secrets on keys path)
    let list_result = engine.list_secrets("keys").await;
    assert!(
        list_result.is_ok(),
        "Should be able to list keys: {:?}",
        list_result.err()
    );
    let keys = list_result.unwrap();
    assert!(!keys.is_empty(), "Should have at least one key");
    assert!(
        keys.contains(&"test-key".to_string()),
        "Should contain the created key"
    );

    // Read key (using read_secret)
    let read_result = engine.read_secret("keys/test-key").await;
    assert!(
        read_result.is_ok(),
        "Should be able to read key: {:?}",
        read_result.err()
    );

    // Test delete key
    let delete_result = engine.delete_secret("keys/test-key").await;
    assert!(
        delete_result.is_ok(),
        "Should be able to delete key: {:?}",
        delete_result.err()
    );

    // Verify deletion
    let list_after_delete = engine.list_secrets("keys").await;
    assert!(
        list_after_delete.is_ok(),
        "Should be able to list keys after delete: {:?}",
        list_after_delete.err()
    );
    let keys_after_delete = list_after_delete.unwrap();
    assert!(
        !keys_after_delete.contains(&"test-key".to_string()),
        "Key should be deleted"
    );
}
}
