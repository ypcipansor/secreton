//! Comprehensive Storage crate tests
//!
//! Tests for storage backend implementations, error handling, and integration

use anyhow::Result;
use secreton_storage::{
    EncryptionMetadata, MockStorageBackend, QueryParams, SecretEntry, SecurityLevel,
    StorageBackend, StorageConfig, StorageError,
};
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(test)]
mod storage_backend_tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_storage_backend_basic_operations() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Test basic store and retrieve
        let entry = SecretEntry::new(
            "test/path".to_string(),
            b"test data".to_vec(),
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

        // Store the entry
        storage.store(&entry).await?;

        // Retrieve by path
        let retrieved = storage.get_by_path("test/path").await?;
        assert!(retrieved.is_some());
        let retrieved_entry = retrieved.unwrap();
        assert_eq!(retrieved_entry.path, "test/path");
        assert_eq!(retrieved_entry.encrypted_data, b"test data");

        // Retrieve by ID
        let retrieved_by_id = storage.get_by_id(entry.id).await?;
        assert!(retrieved_by_id.is_some());
        let retrieved_entry_by_id = retrieved_by_id.unwrap();
        assert_eq!(retrieved_entry_by_id.id, entry.id);

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_update_operations() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Create initial entry
        let mut entry = SecretEntry::new(
            "test/path".to_string(),
            b"initial data".to_vec(),
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

        // Store initial entry
        storage.store(&entry).await?;

        // Update the entry
        entry.encrypted_data = b"updated data".to_vec();
        storage.update(&entry).await?;

        // Verify update
        let retrieved = storage.get_by_path("test/path").await?;
        assert!(retrieved.is_some());
        let retrieved_entry = retrieved.unwrap();
        assert_eq!(retrieved_entry.encrypted_data, b"updated data");

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_delete_operations() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Create and store entry
        let entry = SecretEntry::new(
            "test/delete/path".to_string(),
            b"data to delete".to_vec(),
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

        // Verify entry exists
        let exists_before = storage.exists("test/delete/path").await?;
        assert!(exists_before);

        // Delete by path
        let deleted = storage.delete_by_path("test/delete/path").await?;
        assert!(deleted);

        // Verify entry no longer exists
        let exists_after = storage.exists("test/delete/path").await?;
        assert!(!exists_after);

        // Delete by ID
        let entry2 = SecretEntry::new(
            "test/delete/id".to_string(),
            b"data to delete by id".to_vec(),
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

        storage.store(&entry2).await?;
        let deleted_by_id = storage.delete_by_id(entry2.id).await?;
        assert!(deleted_by_id);

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_list_operations() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Create test entries with different paths
        let entries = vec![
            ("app/users/user1".to_string(), b"user data 1".to_vec()),
            ("app/users/user2".to_string(), b"user data 2".to_vec()),
            ("app/config/db".to_string(), b"db config".to_vec()),
            ("system/health".to_string(), b"health status".to_vec()),
        ];

        for (path, data) in entries {
            let entry = SecretEntry::new(
                path,
                data,
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

        // Test listing all entries
        let all_entries = storage.list(&QueryParams::new()).await?;
        assert_eq!(all_entries.len(), 4);

        // Test listing with path prefix
        let app_entries = storage
            .list(&QueryParams::new().with_path_prefix("app/".to_string()))
            .await?;
        assert_eq!(app_entries.len(), 3);

        let app_keys: Vec<String> = app_entries.into_iter().map(|e| e.path).collect();
        assert!(app_keys.contains(&"app/users/user1".to_string()));
        assert!(app_keys.contains(&"app/users/user2".to_string()));
        assert!(app_keys.contains(&"app/config/db".to_string()));

        // Test listing with security level filter
        let confidential_entries = storage
            .list(&QueryParams::new().with_security_level(SecurityLevel::Internal))
            .await?;
        assert_eq!(confidential_entries.len(), 4);

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_error_conditions() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Test retrieving non-existent entry
        let not_found = storage.get_by_path("nonexistent").await?;
        assert!(not_found.is_none());

        // Test deleting non-existent entry
        let delete_result = storage.delete_by_path("nonexistent").await?;
        assert!(!delete_result);

        // Test updating non-existent entry should fail
        let nonexistent_entry = SecretEntry::new(
            "nonexistent".to_string(),
            b"data".to_vec(),
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

        let update_result = storage.update(&nonexistent_entry).await;
        assert!(update_result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_health_check() -> Result<()> {
        let storage = MockStorageBackend::new();

        let health = storage.health_check().await?;

        assert!(health.is_healthy);
        assert!(health.response_time_ms >= 0.0);
        assert_eq!(health.connections_active, 1); // Mock backend reports 1 active connection

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_statistics() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Add some test data
        for i in 0..5 {
            let entry = SecretEntry::new(
                format!("test/path/{}", i),
                vec![42; 100], // 100 bytes each
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

        let stats = storage.get_stats().await?;

        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.total_size_bytes, 500); // 5 * 100 bytes
        assert_eq!(stats.average_entry_size, 100.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_transaction_simulation() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Test transaction creation (mock implementation)
        let mut tx = storage.begin_transaction().await?;

        // Mock transaction should not fail operations
        let entry = SecretEntry::new(
            "tx_test".to_string(),
            b"transaction data".to_vec(),
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

        tx.store(&entry).await?;
        tx.update(&entry).await?;

        // Commit should succeed
        tx.commit().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_mock_storage_backend_migration() -> Result<()> {
        let storage = MockStorageBackend::new();

        // Migration should complete without errors for mock backend
        storage.migrate().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_secreton_entry_creation_and_validation() -> Result<()> {
        let owner_id = Uuid::new_v4();

        let entry = SecretEntry::new(
            "test/entry".to_string(),
            b"test data".to_vec(),
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            owner_id,
        );

        // Validate entry properties
        assert_eq!(entry.path, "test/entry");
        assert_eq!(entry.encrypted_data, b"test data");
        assert_eq!(entry.security_level, SecurityLevel::Internal);
        assert_eq!(entry.owner_id, owner_id);
        assert_eq!(entry.version, 1);
        assert!(!entry.is_expired());

        // Test metadata and tags
        let entry_with_metadata = entry
            .add_metadata("env".to_string(), "test".to_string())
            .add_tag("important".to_string());

        assert_eq!(
            entry_with_metadata.metadata.get("env"),
            Some(&"test".to_string())
        );
        assert!(entry_with_metadata.tags.contains(&"important".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_query_params_functionality() -> Result<()> {
        let params = QueryParams::new()
            .with_path_prefix("app/".to_string())
            .with_security_level(SecurityLevel::Internal)
            .with_tag("pci".to_string())
            .with_owner(Uuid::new_v4())
            .with_limit(50);

        assert_eq!(params.path_prefix, Some("app/".to_string()));
        assert_eq!(params.security_level, Some(SecurityLevel::Internal));
        assert_eq!(params.tags.len(), 1);
        assert_eq!(params.tags[0], "pci");
        assert_eq!(params.limit, Some(50));

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_error_types() -> Result<()> {
        // Test error display and debug formatting
        let error = StorageError::NotFound {
            resource_type: "SecretEntry".to_string(),
            id: "test-id".to_string(),
        };

        let error_msg = format!("{}", error);
        assert!(error_msg.contains("Not found"));
        assert!(error_msg.contains("SecretEntry"));
        assert!(error_msg.contains("test-id"));

        Ok(())
    }

    #[tokio::test]
    async fn test_encryption_metadata_functionality() -> Result<()> {
        let metadata = EncryptionMetadata {
            algorithm: "aes-256-gcm".to_string(),
            key_id: "test-key-123".to_string(),
            iv: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            auth_tag: Some(vec![0; 16]),
            aad: Some(b"additional data".to_vec()),
            kdf_params: Some(HashMap::from([(
                "salt".to_string(),
                "randomsalt".to_string(),
            )])),
        };

        assert_eq!(metadata.algorithm, "aes-256-gcm");
        assert_eq!(metadata.key_id, "test-key-123");
        assert_eq!(metadata.iv.len(), 12);
        assert_eq!(metadata.auth_tag.as_ref().unwrap().len(), 16);
        assert_eq!(metadata.aad.as_ref().unwrap(), b"additional data");
        assert!(metadata.kdf_params.is_some());

        Ok(())
    }
}

#[cfg(test)]
mod storage_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_config_validation() -> Result<()> {
        let config = StorageConfig {
            backend_type: "memory".to_string(),
            connection_string: "mock://test".to_string(),
            pool_settings: Default::default(),
            encryption_enabled: true,
            compression_enabled: false,
            backup_enabled: true,
            cache_enabled: true,
        };

        assert_eq!(config.backend_type, "memory");
        assert!(config.encryption_enabled);
        assert!(!config.compression_enabled);
        assert!(config.backup_enabled);
        assert!(config.cache_enabled);

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_storage_operations() -> Result<()> {
        let storage = std::sync::Arc::new(MockStorageBackend::new());
        let mut handles = Vec::new();

        // Test concurrent writes
        for i in 0..10 {
            let storage_clone = storage.clone();
            let handle = tokio::spawn(async move {
                let entry = SecretEntry::new(
                    format!("concurrent/path/{}", i),
                    format!("data {}", i).as_bytes().to_vec(),
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

        // Wait for all writes to complete
        for handle in handles {
            handle.await??;
        }

        // Verify all entries were stored
        let all_entries = storage.list(&QueryParams::new()).await?;
        assert_eq!(all_entries.len(), 10);

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_performance_benchmarks() -> Result<()> {
        let storage = MockStorageBackend::new();
        let num_operations = 100;

        // Benchmark writes
        let write_start = std::time::Instant::now();
        for i in 0..num_operations {
            let entry = SecretEntry::new(
                format!("perf/path/{}", i),
                vec![42; 1024], // 1KB each
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

        // Benchmark reads
        let read_start = std::time::Instant::now();
        for i in 0..num_operations {
            let _ = storage.get_by_path(&format!("perf/path/{}", i)).await?;
        }
        let read_duration = read_start.elapsed();

        // Performance assertions (should be fast for in-memory storage)
        assert!(write_duration.as_secs() < 5, "Write performance too slow");
        assert!(read_duration.as_secs() < 2, "Read performance too slow");

        println!(
            "Write performance: {} ops in {:?}",
            num_operations, write_duration
        );
        println!(
            "Read performance: {} ops in {:?}",
            num_operations, read_duration
        );

        Ok(())
    }
}
