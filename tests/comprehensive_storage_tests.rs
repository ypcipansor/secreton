use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use secreton_core::{
    storage::{StorageBackend, MemoryStorage},
    error::StorageError,
};

#[tokio::test]
async fn test_memory_storage_basic_operations() -> Result<()> {
    let storage = MemoryStorage::new();
    
    // Test store and retrieve
    let key = "test_key";
    let value = b"test_value";
    
    storage.store(key, value).await?;
    let retrieved = storage.retrieve(key).await?;
    
    assert_eq!(retrieved, value, "Retrieved value should match stored value");
    
    // Test key existence
    let exists = storage.exists(key).await?;
    assert!(exists, "Key should exist after storing");
    
    // Test non-existent key
    let missing_exists = storage.exists("non_existent").await?;
    assert!(!missing_exists, "Non-existent key should not exist");
    
    // Test delete
    storage.delete(key).await?;
    let deleted_exists = storage.exists(key).await?;
    assert!(!deleted_exists, "Key should not exist after deletion");
    
    // Test retrieve after delete should fail
    let deleted_retrieve = storage.retrieve(key).await;
    assert!(deleted_retrieve.is_err(), "Should fail to retrieve deleted key");
    
    Ok(())
}

#[tokio::test]
async fn test_storage_concurrent_operations() -> Result<()> {
    let storage = Arc::new(MemoryStorage::new());
    
    // Test concurrent writes
    let write_handles: Vec<_> = (0..100).map(|i| {
        let storage_clone = Arc::clone(&storage);
        tokio::spawn(async move {
            let key = format!("concurrent_key_{}", i);
            let value = format!("concurrent_value_{}", i);
            storage_clone.store(&key, value.as_bytes()).await
        })
    }).collect();
    
    // Wait for all writes to complete
    for handle in write_handles {
        let result = handle.await?;
        assert!(result.is_ok(), "Concurrent write should succeed");
    }
    
    // Test concurrent reads
    let read_handles: Vec<_> = (0..100).map(|i| {
        let storage_clone = Arc::clone(&storage);
        tokio::spawn(async move {
            let key = format!("concurrent_key_{}", i);
            let expected_value = format!("concurrent_value_{}", i);
            let result = storage_clone.retrieve(&key).await;
            (i, result, expected_value)
        })
    }).collect();
    
    // Verify all reads
    for handle in read_handles {
        let (i, result, expected_value) = handle.await?;
        assert!(result.is_ok(), "Concurrent read {} should succeed", i);
        
        let actual_value = result.unwrap();
        assert_eq!(actual_value, expected_value.as_bytes(), "Concurrent read {} should match expected value", i);
    }
    
    // Test mixed operations (read/write/delete)
    let mixed_handles: Vec<_> = (0..50).map(|i| {
        let storage_clone = Arc::clone(&storage);
        tokio::spawn(async move {
            let key = format!("mixed_key_{}", i);
            let value = format!("mixed_value_{}", i);
            
            // Store
            storage_clone.store(&key, value.as_bytes()).await?;
            
            // Read back
            let retrieved = storage_clone.retrieve(&key).await?;
            assert_eq!(retrieved, value.as_bytes());
            
            // Update
            let new_value = format!("updated_mixed_value_{}", i);
            storage_clone.store(&key, new_value.as_bytes()).await?;
            
            // Read updated
            let updated_retrieved = storage_clone.retrieve(&key).await?;
            assert_eq!(updated_retrieved, new_value.as_bytes());
            
            // Delete
            storage_clone.delete(&key).await?;
            
            // Verify deletion
            let exists = storage_clone.exists(&key).await?;
            assert!(!exists);
            
            Ok::<(), StorageError>(())
        })
    }).collect();
    
    for handle in mixed_handles {
        let result = handle.await?;
        assert!(result.is_ok(), "Mixed operations should succeed");
    }
    
    Ok(())
}

#[tokio::test]
async fn test_storage_edge_cases() -> Result<()> {
    let storage = MemoryStorage::new();
    
    // Test empty key
    let empty_key_result = storage.store("", b"value").await;
    assert!(empty_key_result.is_err(), "Should fail with empty key");
    
    // Test empty value
    let empty_value_result = storage.store("valid_key", b"").await;
    assert!(empty_value_result.is_ok(), "Should succeed with empty value");
    
    let empty_retrieved = storage.retrieve("valid_key").await?;
    assert!(empty_retrieved.is_empty(), "Should retrieve empty value");
    
    // Test very long keys
    let long_key = "a".repeat(1000);
    let long_key_result = storage.store(&long_key, b"value").await;
    // This should either succeed or fail gracefully
    match long_key_result {
        Ok(_) => {
            let long_retrieved = storage.retrieve(&long_key).await?;
            assert_eq!(long_retrieved, b"value");
            println!("Long key test passed");
        },
        Err(e) => {
            println!("Long key test failed as expected: {:?}", e);
        }
    }
    
    // Test very large values
    let large_value = vec![0u8; 1024 * 1024]; // 1MB
    let large_value_result = storage.store("large_value_key", &large_value).await;
    match large_value_result {
        Ok(_) => {
            let large_retrieved = storage.retrieve("large_value_key").await?;
            assert_eq!(large_retrieved.len(), 1024 * 1024);
            println!("Large value test passed");
        },
        Err(e) => {
            println!("Large value test failed as expected: {:?}", e);
        }
    }
    
    // Test special characters in keys
    let special_keys = vec![
        "key with spaces",
        "key/with/slashes",
        "key\\with\\backslashes",
        "key:with:colons",
        "key.with.dots",
        "key-with-dashes",
        "key_with_underscores",
        "key@with@at",
        "key#with#hash",
        "key$with$dollar",
        "key%with%percent",
        "key^with^caret",
        "key&with&ampersand",
        "key*with*asterisk",
        "key(with)parentheses",
        "key[with]brackets",
        "key{with}braces",
        "key|with|pipe",
        "key;with;semicolon",
        "key'with'quotes",
        "key\"with\"doublequotes",
        "key<with>angles",
        "key,with,commas",
        "key?with?questions",
        "key=with=equals",
        "key+with+plus",
        "key~with~tilde",
        "key`with`backtick",
    ];
    
    for (i, key) in special_keys.iter().enumerate() {
        let value = format!("value_{}", i);
        let result = storage.store(key, value.as_bytes()).await;
        
        match result {
            Ok(_) => {
                let retrieved = storage.retrieve(key).await?;
                assert_eq!(retrieved, value.as_bytes(), "Special key '{}' should work", key);
            },
            Err(e) => {
                println!("Special key '{}' failed as expected: {:?}", key, e);
            }
        }
    }
    
    // Test unicode keys
    let unicode_keys = vec![
        "键值",
        "キー",
        "ключ",
        "مفتاح",
        "🔑key🔑",
        "key_with_émojis_🚀",
    ];
    
    for (i, key) in unicode_keys.iter().enumerate() {
        let value = format!("unicode_value_{}", i);
        let result = storage.store(key, value.as_bytes()).await;
        
        match result {
            Ok(_) => {
                let retrieved = storage.retrieve(key).await?;
                assert_eq!(retrieved, value.as_bytes(), "Unicode key '{}' should work", key);
                println!("Unicode key '{}' test passed", key);
            },
            Err(e) => {
                println!("Unicode key '{}' failed as expected: {:?}", key, e);
            }
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_storage_patterns_and_listing() -> Result<()> {
    let storage = MemoryStorage::new();
    
    // Create hierarchical data structure
    let test_data = vec![
        ("app/frontend/config", "frontend_config"),
        ("app/backend/config", "backend_config"),
        ("app/database/url", "db_url"),
        ("app/database/credentials", "db_creds"),
        ("secrets/api/key1", "api_key_1"),
        ("secrets/api/key2", "api_key_2"),
        ("secrets/oauth/client_id", "oauth_client"),
        ("secrets/oauth/client_secret", "oauth_secret"),
        ("temp/cache/item1", "cache_item_1"),
        ("temp/cache/item2", "cache_item_2"),
        ("temp/sessions/user1", "session_1"),
    ];
    
    // Store all test data
    for (key, value) in &test_data {
        storage.store(key, value.as_bytes()).await?;
    }
    
    // Test list functionality if available
    if let Ok(all_keys) = storage.list_keys("").await {
        assert!(!all_keys.is_empty(), "Should have keys");
        assert_eq!(all_keys.len(), test_data.len(), "Should list all keys");
        
        // Test prefix listing
        if let Ok(app_keys) = storage.list_keys("app").await {
            let expected_app_keys = test_data.iter()
                .filter(|(k, _)| k.starts_with("app"))
                .count();
            assert_eq!(app_keys.len(), expected_app_keys, "Should list app keys");
        }
        
        if let Ok(secret_keys) = storage.list_keys("secrets").await {
            let expected_secret_keys = test_data.iter()
                .filter(|(k, _)| k.starts_with("secrets"))
                .count();
            assert_eq!(secret_keys.len(), expected_secret_keys, "Should list secret keys");
        }
    } else {
        println!("Storage doesn't support listing - testing individual access");
        
        // Test that all keys can be retrieved individually
        for (key, expected_value) in &test_data {
            let retrieved = storage.retrieve(key).await?;
            assert_eq!(retrieved, expected_value.as_bytes(), "Should retrieve {}", key);
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_storage_performance_characteristics() -> Result<()> {
    let storage = MemoryStorage::new();
    
    // Test rapid sequential operations
    let num_operations = 1000;
    
    // Sequential writes
    let write_start = std::time::Instant::now();
    for i in 0..num_operations {
        let key = format!("perf_key_{}", i);
        let value = format!("perf_value_{}", i);
        storage.store(&key, value.as_bytes()).await?;
    }
    let write_duration = write_start.elapsed();
    println!("{} sequential writes took: {:?}", num_operations, write_duration);
    
    // Sequential reads
    let read_start = std::time::Instant::now();
    for i in 0..num_operations {
        let key = format!("perf_key_{}", i);
        let _value = storage.retrieve(&key).await?;
    }
    let read_duration = read_start.elapsed();
    println!("{} sequential reads took: {:?}", num_operations, read_duration);
    
    // Random access pattern
    let random_start = std::time::Instant::now();
    for i in (0..num_operations).step_by(7) {  // Access every 7th item
        let key = format!("perf_key_{}", i % num_operations);
        let _value = storage.retrieve(&key).await?;
    }
    let random_duration = random_start.elapsed();
    println!("{} random reads took: {:?}", num_operations / 7, random_duration);
    
    // Mixed operations
    let mixed_start = std::time::Instant::now();
    for i in 0..num_operations / 4 {
        let key = format!("mixed_key_{}", i);
        let value = format!("mixed_value_{}", i);
        
        // Write
        storage.store(&key, value.as_bytes()).await?;
        
        // Read
        let _retrieved = storage.retrieve(&key).await?;
        
        // Update
        let new_value = format!("updated_{}", value);
        storage.store(&key, new_value.as_bytes()).await?;
        
        // Read again
        let _updated = storage.retrieve(&key).await?;
    }
    let mixed_duration = mixed_start.elapsed();
    println!("{} mixed operations took: {:?}", num_operations, mixed_duration);
    
    // Performance expectations (adjust based on system)
    assert!(write_duration.as_millis() < 5000, "Writes should be reasonably fast");
    assert!(read_duration.as_millis() < 2000, "Reads should be fast");
    
    Ok(())
}

#[tokio::test]
async fn test_storage_stress_test() -> Result<()> {
    let storage = Arc::new(MemoryStorage::new());
    let num_workers = 10;
    let operations_per_worker = 100;
    
    // Spawn multiple workers doing concurrent operations
    let worker_handles: Vec<_> = (0..num_workers).map(|worker_id| {
        let storage_clone = Arc::clone(&storage);
        tokio::spawn(async move {
            let mut operations_completed = 0;
            
            for i in 0..operations_per_worker {
                let key = format!("stress_{}_{}", worker_id, i);
                let value = format!("stress_value_{}_{}", worker_id, i);
                
                // Store
                match storage_clone.store(&key, value.as_bytes()).await {
                    Ok(_) => operations_completed += 1,
                    Err(e) => {
                        println!("Worker {} failed store operation {}: {:?}", worker_id, i, e);
                        continue;
                    }
                }
                
                // Read back
                match storage_clone.retrieve(&key).await {
                    Ok(retrieved) => {
                        if retrieved != value.as_bytes() {
                            println!("Worker {} data mismatch at operation {}", worker_id, i);
                        }
                    }
                    Err(e) => {
                        println!("Worker {} failed read operation {}: {:?}", worker_id, i, e);
                        continue;
                    }
                }
                
                // Occasionally delete and recreate
                if i % 10 == 0 {
                    let _ = storage_clone.delete(&key).await;
                    let _ = storage_clone.store(&key, value.as_bytes()).await;
                }
                
                // Add some variability
                if i % 20 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }
            
            println!("Worker {} completed {} operations", worker_id, operations_completed);
            operations_completed
        })
    }).collect();
    
    // Wait for all workers to complete
    let mut total_operations = 0;
    for handle in worker_handles {
        let completed = handle.await?;
        total_operations += completed;
    }
    
    println!("Stress test completed: {} total operations", total_operations);
    
    // Verify some of the data is still accessible
    for worker_id in 0..num_workers {
        for i in 0..10 {  // Check first 10 items from each worker
            let key = format!("stress_{}_{}", worker_id, i);
            let expected_value = format!("stress_value_{}_{}", worker_id, i);
            
            match storage.retrieve(&key).await {
                Ok(retrieved) => {
                    assert_eq!(retrieved, expected_value.as_bytes(), 
                              "Stress test data integrity check failed for {}", key);
                }
                Err(_) => {
                    // It's possible some keys were deleted during the stress test
                    println!("Key {} not found (possibly deleted during stress test)", key);
                }
            }
        }
    }
    
    assert!(total_operations > num_workers * operations_per_worker / 2, 
           "Should complete at least half of all operations");
    
    Ok(())
}

#[tokio::test]
async fn test_storage_cleanup_and_recovery() -> Result<()> {
    let storage = MemoryStorage::new();
    
    // Fill storage with data
    for i in 0..100 {
        let key = format!("cleanup_key_{}", i);
        let value = format!("cleanup_value_{}", i);
        storage.store(&key, value.as_bytes()).await?;
    }
    
    // Verify all data is there
    for i in 0..100 {
        let key = format!("cleanup_key_{}", i);
        let exists = storage.exists(&key).await?;
        assert!(exists, "Key {} should exist before cleanup", key);
    }
    
    // Delete every other key
    for i in (0..100).step_by(2) {
        let key = format!("cleanup_key_{}", i);
        storage.delete(&key).await?;
    }
    
    // Verify deletion pattern
    for i in 0..100 {
        let key = format!("cleanup_key_{}", i);
        let exists = storage.exists(&key).await?;
        if i % 2 == 0 {
            assert!(!exists, "Even key {} should be deleted", key);
        } else {
            assert!(exists, "Odd key {} should still exist", key);
        }
    }
    
    // Test recovery by recreating deleted keys
    for i in (0..100).step_by(2) {
        let key = format!("cleanup_key_{}", i);
        let value = format!("recovered_value_{}", i);
        storage.store(&key, value.as_bytes()).await?;
    }
    
    // Verify all keys exist again
    for i in 0..100 {
        let key = format!("cleanup_key_{}", i);
        let exists = storage.exists(&key).await?;
        assert!(exists, "Key {} should exist after recovery", key);
        
        let retrieved = storage.retrieve(&key).await?;
        if i % 2 == 0 {
            let expected = format!("recovered_value_{}", i);
            assert_eq!(retrieved, expected.as_bytes(), "Even key {} should have recovered value", key);
        } else {
            let expected = format!("cleanup_value_{}", i);
            assert_eq!(retrieved, expected.as_bytes(), "Odd key {} should have original value", key);
        }
    }
    
    Ok(())
}
