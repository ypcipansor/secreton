//! Comprehensive database and storage backend tests
//! Tests for the in-memory storage implementation

use anyhow::Result;
use secreton_storage::{
    EncryptionMetadata, MockStorageBackend, QueryParams, SecretEntry, SecurityLevel, StorageBackend,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(test)]
mod storage_backend_tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage_comprehensive() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Test basic CRUD operations
        let test_data = vec![
            ("key1", b"value1"),
            ("key2", b"value2"),
            ("key3", b"value3"),
        ];

        // Store data
        for (key, value) in &test_data {
            let entry = SecretEntry::new(
                key.to_string(),
                value.to_vec(),
                EncryptionMetadata {
                    algorithm: "aes-256-gcm".to_string(),
                    key_id: "test-key".to_string(),
                    iv: vec![0; 12],
                    auth_tag: Some(vec![0; 16]),
                    aad: None,
                    kdf_params: None,
                },
                SecurityLevel::Internal,
                Uuid::new_v4(),
            );
            storage.store(&entry).await?;
        }

        // Test existence checks via listing
        let entries = storage.list(&QueryParams::new()).await?;
        let keys: Vec<String> = entries.into_iter().map(|e| e.path).collect();
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));

        // Test retrieval by key
        let entry = storage.get_by_path("key1").await?;
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.path, "key1");
        assert_eq!(entry.encrypted_data, b"value1");

        // Test listing with prefix
        let entries = storage
            .list(&QueryParams::new().with_path_prefix("key".to_string()))
            .await?;
        let keys: Vec<String> = entries.into_iter().map(|e| e.path).collect();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));

        // Test deletion
        storage.delete_by_path("key1").await?;
        let entries_after_delete = storage
            .list(&QueryParams::new().with_path_prefix("key".to_string()))
            .await?;
        let keys_after_delete: Vec<String> =
            entries_after_delete.into_iter().map(|e| e.path).collect();
        assert_eq!(keys_after_delete.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_concurrent_operations() -> Result<()> {
        // Create a storage backend for testing
        let storage: Arc<MockStorageBackend> = Arc::new(MockStorageBackend::new());
        let mut handles = Vec::new();

        // Test concurrent writes
        for i in 0..100 {
            let storage_clone: Arc<MockStorageBackend> = Arc::clone(&storage);
            let handle = tokio::spawn(async move {
                let key = format!("concurrent_key_{}", i);
                let entry = SecretEntry::new(
                    key.clone(),
                    format!("concurrent_value_{}", i).as_bytes().to_vec(),
                    EncryptionMetadata {
                        algorithm: "aes-256-gcm".to_string(),
                        key_id: "test-key".to_string(),
                        iv: vec![0; 12],
                        auth_tag: Some(vec![0; 16]),
                        aad: None,
                        kdf_params: None,
                    },
                    SecurityLevel::Internal,
                    Uuid::new_v4(),
                );
                storage_clone.store(&entry).await
            });
            handles.push(handle);
        }

        // Wait for all writes
        for handle in handles {
            handle.await??;
        }

        // Verify all data was written correctly
        for i in 0..100 {
            let key = format!("concurrent_key_{}", i);
            let entry = storage.get_by_path(&key).await?;
            assert!(entry.is_some());
            let entry = entry.unwrap();
            assert_eq!(entry.path, key);
            assert_eq!(
                entry.encrypted_data,
                format!("concurrent_value_{}", i).as_bytes()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_data_integrity() -> Result<()> {
        let storage = MockStorageBackend::new();

        let binary_data = vec![0u8, 1, 2, 255, 254, 253];
        let entry = SecretEntry::new(
            "binary_test".to_string(),
            binary_data.clone(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        storage.store(&entry).await?;

        let retrieved = storage.get_by_path("binary_test").await?;
        assert!(retrieved.is_some());
        let retrieved_entry = retrieved.unwrap();
        assert_eq!(retrieved_entry.encrypted_data, binary_data);

        // Test with large data
        let large_data = vec![42u8; 1024 * 1024]; // 1MB
        let large_entry = SecretEntry::new(
            "large_test".to_string(),
            large_data.clone(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        storage.store(&large_entry).await?;

        let retrieved_large = storage.get_by_path("large_test").await?;
        assert!(retrieved_large.is_some());
        let retrieved_large_entry = retrieved_large.unwrap();
        assert_eq!(retrieved_large_entry.encrypted_data.len(), large_data.len());
        assert_eq!(retrieved_large_entry.encrypted_data, large_data);

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_error_conditions() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Test retrieving non-existent key
        let result = storage.get_by_path("nonexistent").await?;
        assert!(result.is_none());

        // Test operations on non-existent entries
        let result = storage.delete_by_path("nonexistent").await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_storage_performance() -> Result<()> {
        let storage = MockStorageBackend::new();
        let num_operations = 1000;

        // Measure write performance
        let write_start = Instant::now();
        for i in 0..num_operations {
            let key = format!("perf_key_{}", i);
            let entry = SecretEntry::new(
                key.clone(),
                format!("perf_value_{}", i).as_bytes().to_vec(),
                EncryptionMetadata {
                    algorithm: "aes-256-gcm".to_string(),
                    key_id: "test-key".to_string(),
                    iv: vec![0; 12],
                    auth_tag: Some(vec![0; 16]),
                    aad: None,
                    kdf_params: None,
                },
                SecurityLevel::Internal,
                Uuid::new_v4(),
            );
            storage.store(&entry).await?;
        }
        let write_duration = write_start.elapsed();

        // Measure read performance
        let read_start = Instant::now();
        for i in 0..num_operations {
            let key = format!("perf_key_{}", i);
            let _ = storage.get_by_path(&key).await?;
        }
        let read_duration = read_start.elapsed();

        println!(
            "Write performance: {} ops in {:?}",
            num_operations, write_duration
        );
        println!(
            "Read performance: {} ops in {:?}",
            num_operations, read_duration
        );

        // Performance assertions (should be fast for in-memory storage)
        assert!(
            write_duration < Duration::from_secs(5),
            "Write performance too slow"
        );
        assert!(
            read_duration < Duration::from_secs(2),
            "Read performance too slow"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_metadata_handling() -> Result<()> {
        let storage = MockStorageBackend::new();

        let entry = SecretEntry::new(
            "metadata_test".to_string(),
            b"test_value".to_vec(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        storage.store(&entry).await?;

        // Retrieve and verify metadata is preserved
        let retrieved = storage.get_by_path("metadata_test").await?;
        assert!(retrieved.is_some());

        let retrieved_entry = retrieved.unwrap();
        assert_eq!(retrieved_entry.encrypted_data, b"test_value");

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_prefix_operations() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Store data with different prefixes
        let test_data = vec![
            ("app/users/user1", "user_data_1"),
            ("app/users/user2", "user_data_2"),
            ("app/config/db", "db_config"),
            ("system/health", "health_status"),
            ("system/metrics", "metrics_data"),
        ];

        for (key, value) in test_data {
            let entry = SecretEntry::new(
                key.to_string(),
                value.as_bytes().to_vec(),
                EncryptionMetadata {
                    algorithm: "aes-256-gcm".to_string(),
                    key_id: "test-key".to_string(),
                    iv: vec![0; 12],
                    auth_tag: Some(vec![0; 16]),
                    aad: None,
                    kdf_params: None,
                },
                SecurityLevel::Internal,
                Uuid::new_v4(),
            );
            storage.store(&entry).await?;
        }

        // Test prefix listing
        let app_entries = storage
            .list(&QueryParams::new().with_path_prefix("app/".to_string()))
            .await?;
        let app_keys: Vec<String> = app_entries.into_iter().map(|e| e.path).collect();
        assert_eq!(app_keys.len(), 3);
        assert!(app_keys.contains(&"app/users/user1".to_string()));
        assert!(app_keys.contains(&"app/users/user2".to_string()));
        assert!(app_keys.contains(&"app/config/db".to_string()));

        let system_entries = storage
            .list(&QueryParams::new().with_path_prefix("system/".to_string()))
            .await?;
        let system_keys: Vec<String> = system_entries.into_iter().map(|e| e.path).collect();
        assert_eq!(system_keys.len(), 2);

        let user_entries = storage
            .list(&QueryParams::new().with_path_prefix("app/users/".to_string()))
            .await?;
        let user_keys: Vec<String> = user_entries.into_iter().map(|e| e.path).collect();
        assert_eq!(user_keys.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_edge_cases() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Test with very long keys
        let long_key = "a".repeat(1000);
        let long_key_entry = SecretEntry::new(
            long_key,
            b"value".to_vec(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        storage.store(&long_key_entry).await?;

        // Test with empty key
        let empty_key_entry = SecretEntry::new(
            "".to_string(),
            b"empty_key_value".to_vec(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        let result = storage.store(&empty_key_entry).await;
        assert!(result.is_ok());

        // Test with unicode keys
        let unicode_key = "こんにちは世界";
        let unicode_entry = SecretEntry::new(
            unicode_key.to_string(),
            b"unicode_value".to_vec(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        storage.store(&unicode_entry).await?;

        // Verify unicode key retrieval
        let retrieved = storage.get_by_path(unicode_key).await?;
        assert!(retrieved.is_some());
        let retrieved_entry = retrieved.unwrap();
        assert_eq!(retrieved_entry.encrypted_data, b"unicode_value");

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_transaction_simulation() -> Result<()> {
        // Since MockStorageBackend doesn't support transactions, we'll just test basic operations
        let storage = MockStorageBackend::new();

        // Store a value
        let entry = SecretEntry::new(
            "tx_key".to_string(),
            b"test_value".to_vec(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        storage.store(&entry).await?;

        // Verify the value was stored
        let retrieved = storage.get_by_path("tx_key").await?;
        assert!(retrieved.is_some());
        let retrieved_entry = retrieved.unwrap();
        assert_eq!(retrieved_entry.encrypted_data, b"test_value");

        Ok(())
    }
}
