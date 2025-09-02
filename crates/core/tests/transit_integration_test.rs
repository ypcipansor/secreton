//! Integration tests for Transit Secrets Engine

use base64::{engine::general_purpose, Engine as _};
use secreton_core::secrets::engine::{
    CreateKeyRequest, DecryptRequest, EncryptRequest, SecretsEngine, TransitSecretsEngine,
};
use secreton_core::storage::MemoryStorage;
use std::sync::Arc;

#[tokio::test]
async fn test_transit_engine_integration() {
    let storage = Arc::new(MemoryStorage::new("memory://").await.unwrap());
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
    let storage = Arc::new(MemoryStorage::new("memory://").await.unwrap());
    let engine = TransitSecretsEngine::new(storage);

    // Test SecretsEngine interface
    use serde_json::json;

    // Create a test secret
    let test_data = json!({"test": "data"});
    let secret_result = engine
        .create_secret("test/key", test_data.clone(), None)
        .await;
    assert!(secret_result.is_ok(), "Should be able to create secret");

    // Read the secret back
    let read_result = engine.read_secret("test/key").await;
    assert!(read_result.is_ok(), "Should be able to read secret");

    // List secrets
    let list_result = engine.list_secrets("test").await;
    assert!(list_result.is_ok(), "Should be able to list secrets");
    let keys = list_result.unwrap();
    assert!(!keys.is_empty(), "Should have at least one secret");
    assert!(
        keys.contains(&"key".to_string()),
        "Should contain the created key"
    );

    // Update secret
    let updated_data = json!({"test": "updated_data"});
    let update_result = engine.update_secret("test/key", updated_data, None).await;
    assert!(update_result.is_ok(), "Should be able to update secret");

    // Delete secret
    let delete_result = engine.delete_secret("test/key").await;
    assert!(delete_result.is_ok(), "Should be able to delete secret");

    // Verify deletion
    let list_after_delete = engine.list_secrets("test").await;
    assert!(
        list_after_delete.is_ok(),
        "Should be able to list after delete"
    );
    let keys_after_delete = list_after_delete.unwrap();
    assert!(
        !keys_after_delete.contains(&"key".to_string()),
        "Key should be deleted"
    );
}
