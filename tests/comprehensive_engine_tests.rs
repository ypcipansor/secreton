use std::collections::HashMap;
use tokio::time::{sleep, Duration};
use anyhow::Result;
use serde_json::json;
use secreton_core::{
    secrets::{SecretsEngine, SecretsEngineRegistry},
    secrets::secrets_impl::engine::{
        kv::KvSecretsEngine,
        transit::TransitSecretsEngine,
    },
    storage::{StorageBackend, MemoryStorage},
    types::{Secret, SecretMetadata},
    error::SecretsError,
};

async fn create_test_storage() -> Box<dyn StorageBackend> {
    Box::new(MemoryStorage::new())
}

#[tokio::test]
async fn test_secrets_engine_registry() -> Result<()> {
    let mut registry = SecretsEngineRegistry::new();
    
    // Register KV engine
    let kv_storage = create_test_storage().await;
    let kv_engine = Box::new(KvSecretsEngine::new(kv_storage));
    registry.register("kv", kv_engine);
    
    // Register Transit engine  
    let transit_storage = create_test_storage().await;
    let transit_engine = Box::new(TransitSecretsEngine::new(transit_storage));
    registry.register("transit", transit_engine);
    
    // Test engine retrieval
    let kv_retrieved = registry.get("kv");
    assert!(kv_retrieved.is_some(), "Should be able to retrieve KV engine");
    
    let transit_retrieved = registry.get("transit");
    assert!(transit_retrieved.is_some(), "Should be able to retrieve Transit engine");
    
    // Test non-existent engine
    let non_existent = registry.get("non_existent");
    assert!(non_existent.is_none(), "Should return None for non-existent engine");
    
    // Test engine listing
    let engines = registry.list_engines();
    assert!(engines.contains(&"kv".to_string()), "Should list KV engine");
    assert!(engines.contains(&"transit".to_string()), "Should list Transit engine");
    assert_eq!(engines.len(), 2, "Should list exactly 2 engines");
    
    Ok(())
}

#[tokio::test]
async fn test_kv_engine_comprehensive() -> Result<()> {
    let storage = create_test_storage().await;
    let engine = KvSecretsEngine::new(storage);
    
    // Test basic CRUD operations
    let secret_data = json!({
        "username": "admin",
        "password": "secret123",
        "database": "prod_db"
    });
    
    // Create secret
    let create_result = engine.create_secret("database/prod", secret_data.clone(), None).await;
    assert!(create_result.is_ok(), "Should be able to create secret");
    
    let created_secret = create_result.unwrap();
    assert_eq!(created_secret.path, "database/prod");
    assert_eq!(created_secret.data, secret_data);
    
    // Read secret
    let read_result = engine.read_secret("database/prod").await;
    assert!(read_result.is_ok(), "Should be able to read secret");
    
    let read_secret = read_result.unwrap();
    assert_eq!(read_secret.data, secret_data);
    
    // Update secret
    let updated_data = json!({
        "username": "admin",
        "password": "newsecret456",
        "database": "prod_db",
        "updated": true
    });
    
    let update_result = engine.update_secret("database/prod", updated_data.clone(), None).await;
    assert!(update_result.is_ok(), "Should be able to update secret");
    
    // Verify update
    let updated_read = engine.read_secret("database/prod").await?;
    assert_eq!(updated_read.data, updated_data);
    assert!(updated_read.metadata.version > 1, "Version should be incremented");
    
    // Test versioning
    let version_1 = engine.read_secret_version("database/prod", 1).await;
    assert!(version_1.is_ok(), "Should be able to read version 1");
    
    let v1_secret = version_1.unwrap();
    assert_eq!(v1_secret.data, secret_data, "Version 1 should have original data");
    
    // List secrets
    let list_result = engine.list_secrets("database").await;
    assert!(list_result.is_ok(), "Should be able to list secrets");
    
    let secrets_list = list_result.unwrap();
    assert!(secrets_list.contains(&"prod".to_string()), "Should contain prod secret");
    
    // Test nested paths
    let nested_secret = json!({"api_key": "key123", "endpoint": "https://api.example.com"});
    let nested_create = engine.create_secret("apps/frontend/config", nested_secret.clone(), None).await;
    assert!(nested_create.is_ok(), "Should be able to create nested secret");
    
    let list_apps = engine.list_secrets("apps").await?;
    assert!(list_apps.contains(&"frontend/config".to_string()), "Should list nested paths");
    
    // Delete secret
    let delete_result = engine.delete_secret("database/prod").await;
    assert!(delete_result.is_ok(), "Should be able to delete secret");
    
    // Verify deletion
    let deleted_read = engine.read_secret("database/prod").await;
    assert!(deleted_read.is_err(), "Should not be able to read deleted secret");
    
    Ok(())
}

#[tokio::test]
async fn test_transit_engine_comprehensive() -> Result<()> {
    let storage = create_test_storage().await;
    let engine = TransitSecretsEngine::new(storage);
    
    // Create multiple key types
    let key_types = vec![
        ("aes-key", "aes256-gcm"),
        ("rsa-key", "rsa-2048"),
        ("ed25519-key", "ed25519"),
        ("ecdsa-key", "ecdsa-p256"),
    ];
    
    for (key_name, key_type) in &key_types {
        let key_data = json!({
            "name": key_name,
            "type": key_type,
            "exportable": true,
            "allow_plaintext_backup": true
        });
        
        let create_result = engine.create_secret("keys", key_data, None).await;
        assert!(create_result.is_ok(), "Should be able to create {} key", key_name);
    }
    
    // List all keys
    let keys_list = engine.list_secrets("keys").await?;
    for (key_name, _) in &key_types {
        assert!(keys_list.contains(&key_name.to_string()), "Should list key: {}", key_name);
    }
    
    // Test encryption/decryption with AES key
    let plaintext = "Hello, World! This is a test message for encryption.";
    let encrypted = engine.encrypt("aes-key", plaintext.as_bytes(), None).await;
    assert!(encrypted.is_ok(), "Should be able to encrypt with AES key");
    
    let encrypted_data = encrypted.unwrap();
    let decrypted = engine.decrypt("aes-key", &encrypted_data, None).await;
    assert!(decrypted.is_ok(), "Should be able to decrypt with AES key");
    
    let decrypted_data = decrypted.unwrap();
    assert_eq!(String::from_utf8(decrypted_data).unwrap(), plaintext, "Decrypted should match original");
    
    // Test signing/verification with signing keys
    let message = b"This is a message to sign";
    
    for (key_name, key_type) in &key_types {
        if key_type.contains("ed25519") || key_type.contains("ecdsa") || key_type.contains("rsa") {
            let sign_result = engine.sign(key_name, message, None).await;
            assert!(sign_result.is_ok(), "Should be able to sign with {}", key_name);
            
            let signature = sign_result.unwrap();
            let verify_result = engine.verify(key_name, message, &signature).await;
            assert!(verify_result.is_ok(), "Should be able to verify signature for {}", key_name);
            
            let is_valid = verify_result.unwrap();
            assert!(is_valid, "Signature should be valid for {}", key_name);
        }
    }
    
    // Test key rotation
    let rotate_result = engine.rotate_key("aes-key").await;
    assert!(rotate_result.is_ok(), "Should be able to rotate AES key");
    
    // Test encryption with rotated key still works
    let post_rotation_encrypted = engine.encrypt("aes-key", plaintext.as_bytes(), None).await;
    assert!(post_rotation_encrypted.is_ok(), "Should still be able to encrypt after rotation");
    
    // Test HMAC operations
    let hmac_result = engine.hmac("aes-key", message).await;
    assert!(hmac_result.is_ok(), "Should be able to generate HMAC");
    
    let hmac_value = hmac_result.unwrap();
    assert!(!hmac_value.is_empty(), "HMAC should not be empty");
    
    // Test random data generation
    let random_32 = engine.random(32).await;
    assert!(random_32.is_ok(), "Should be able to generate 32 bytes of random data");
    
    let random_data = random_32.unwrap();
    assert_eq!(random_data.len(), 32, "Should generate exactly 32 bytes");
    
    let random_64 = engine.random(64).await;
    assert!(random_64.is_ok(), "Should be able to generate 64 bytes of random data");
    
    let random_64_data = random_64.unwrap();
    assert_eq!(random_64_data.len(), 64, "Should generate exactly 64 bytes");
    assert_ne!(random_data, random_64_data[..32], "Random data should be different");
    
    // Test key deletion
    for (key_name, _) in &key_types {
        let delete_result = engine.delete_secret(&format!("keys/{}", key_name)).await;
        assert!(delete_result.is_ok(), "Should be able to delete key: {}", key_name);
    }
    
    // Verify all keys are deleted
    let final_keys_list = engine.list_secrets("keys").await?;
    assert!(final_keys_list.is_empty(), "All keys should be deleted");
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_engine_operations() -> Result<()> {
    let storage = create_test_storage().await;
    let engine = KvSecretsEngine::new(storage);
    
    // Test concurrent secret creation
    let create_handles: Vec<_> = (0..50).map(|i| {
        let engine_ref = &engine;
        tokio::spawn(async move {
            let secret_data = json!({
                "id": i,
                "data": format!("concurrent_secret_{}", i),
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            
            engine_ref.create_secret(&format!("concurrent/{}", i), secret_data, None).await
        })
    }).collect();
    
    for handle in create_handles {
        let result = handle.await?;
        assert!(result.is_ok(), "Concurrent create should succeed");
    }
    
    // Test concurrent reads
    let read_handles: Vec<_> = (0..50).map(|i| {
        let engine_ref = &engine;
        tokio::spawn(async move {
            engine_ref.read_secret(&format!("concurrent/{}", i)).await
        })
    }).collect();
    
    for (i, handle) in read_handles.into_iter().enumerate() {
        let result = handle.await?;
        assert!(result.is_ok(), "Concurrent read {} should succeed", i);
        
        let secret = result.unwrap();
        let expected_data = json!({
            "id": i,
            "data": format!("concurrent_secret_{}", i)
        });
        
        // Check essential fields (timestamp might vary slightly)
        assert_eq!(secret.data.get("id"), expected_data.get("id"));
        assert_eq!(secret.data.get("data"), expected_data.get("data"));
    }
    
    Ok(())
}

#[tokio::test]
async fn test_error_conditions_and_edge_cases() -> Result<()> {
    let storage = create_test_storage().await;
    let kv_engine = KvSecretsEngine::new(storage);
    
    // Test invalid paths
    let empty_path_result = kv_engine.create_secret("", json!({"test": "data"}), None).await;
    assert!(empty_path_result.is_err(), "Should fail with empty path");
    
    let slash_only_result = kv_engine.create_secret("/", json!({"test": "data"}), None).await;
    assert!(slash_only_result.is_err(), "Should fail with slash-only path");
    
    // Test very long paths
    let long_path = "a".repeat(1000);
    let long_path_result = kv_engine.create_secret(&long_path, json!({"test": "data"}), None).await;
    // This should either succeed or fail gracefully
    println!("Long path result: {:?}", long_path_result.is_ok());
    
    // Test reading non-existent secrets
    let missing_read = kv_engine.read_secret("does/not/exist").await;
    assert!(missing_read.is_err(), "Should fail reading non-existent secret");
    
    // Test updating non-existent secrets
    let missing_update = kv_engine.update_secret("does/not/exist", json!({"new": "data"}), None).await;
    assert!(missing_update.is_err(), "Should fail updating non-existent secret");
    
    // Test deleting non-existent secrets
    let missing_delete = kv_engine.delete_secret("does/not/exist").await;
    assert!(missing_delete.is_err(), "Should fail deleting non-existent secret");
    
    // Test very large secret data
    let large_data = json!({
        "large_field": "x".repeat(1024 * 1024), // 1MB string
        "metadata": {
            "size": "1MB",
            "type": "stress_test"
        }
    });
    
    let large_create = kv_engine.create_secret("stress/large", large_data, None).await;
    match large_create {
        Ok(_) => {
            println!("Successfully stored 1MB secret");
            let large_read = kv_engine.read_secret("stress/large").await;
            assert!(large_read.is_ok(), "Should be able to read large secret");
        },
        Err(e) => {
            println!("Large secret creation failed (expected): {:?}", e);
        }
    }
    
    // Test invalid JSON handling
    let invalid_options = Some(json!("invalid_options_format"));
    let invalid_result = kv_engine.create_secret("test/invalid", json!({"test": "data"}), invalid_options).await;
    // Should either handle gracefully or fail appropriately
    println!("Invalid options result: {:?}", invalid_result.is_ok());
    
    Ok(())
}

#[tokio::test]
async fn test_secrets_metadata_operations() -> Result<()> {
    let storage = create_test_storage().await;
    let engine = KvSecretsEngine::new(storage);
    
    // Create secret with custom metadata
    let secret_data = json!({"password": "secret123"});
    let metadata_options = Some(json!({
        "ttl": 3600,
        "max_versions": 5,
        "custom_metadata": {
            "owner": "team-alpha",
            "environment": "production",
            "compliance": "required"
        }
    }));
    
    let create_result = engine.create_secret("app/database", secret_data, metadata_options).await;
    assert!(create_result.is_ok(), "Should create secret with metadata");
    
    let secret = create_result.unwrap();
    
    // Verify metadata is properly set
    if let Some(custom_meta) = &secret.metadata.custom_metadata {
        assert_eq!(custom_meta.get("owner").and_then(|v| v.as_str()), Some("team-alpha"));
        assert_eq!(custom_meta.get("environment").and_then(|v| v.as_str()), Some("production"));
    }
    
    // Test metadata queries
    let read_result = engine.read_secret("app/database").await?;
    assert_eq!(read_result.metadata.version, 1, "Initial version should be 1");
    
    // Test multiple updates to verify versioning
    for i in 2..=5 {
        let updated_data = json!({"password": format!("secret{}", i), "version": i});
        let update_result = engine.update_secret("app/database", updated_data, None).await;
        assert!(update_result.is_ok(), "Update {} should succeed", i);
        
        let updated_secret = engine.read_secret("app/database").await?;
        assert_eq!(updated_secret.metadata.version, i as u32, "Version should be {}", i);
    }
    
    // Test reading specific versions
    let version_2 = engine.read_secret_version("app/database", 2).await?;
    assert_eq!(version_2.data.get("password").and_then(|v| v.as_str()), Some("secret2"));
    
    let version_5 = engine.read_secret_version("app/database", 5).await?;
    assert_eq!(version_5.data.get("password").and_then(|v| v.as_str()), Some("secret5"));
    
    Ok(())
}
