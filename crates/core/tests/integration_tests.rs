// Integration tests for Secreton Core
// NOTE: This test file is currently disabled as it uses MemorySecretsEngine which doesn't exist.
// The integration tests need to be rewritten to use actual secrets engines.

#[cfg(feature = "disabled")]
mod disabled_integration_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;
    use secreton_core::secrets::engine::SecretsEngineRegistry;

    #[tokio::test]
    async fn test_registry_multiple_engines() {
        let mut registry = SecretsEngineRegistry::new();

        // Register multiple engines
        let memory1 = MemorySecretsEngine::new();
        let memory2 = MemorySecretsEngine::new();

        assert!(registry.register(memory1).is_ok());
        // Second memory engine should fail (duplicate type)
        assert!(registry.register(memory2).is_err());
    }

    #[tokio::test]
    async fn test_registry_get_engine() {
        let mut registry = SecretsEngineRegistry::new();
        let engine = MemorySecretsEngine::new();

        registry.register(engine).unwrap();

        let retrieved = registry.get_engine("memory");
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_registry_get_nonexistent_engine() {
        let registry = SecretsEngineRegistry::new();
        let retrieved = registry.get_engine("nonexistent");
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_registry_list_engines() {
        let mut registry = SecretsEngineRegistry::new();
        let engine = MemorySecretsEngine::new();

        registry.register(engine).unwrap();

        let engines = registry.list_engines();
        assert_eq!(engines.len(), 1);
        assert_eq!(engines[0], "memory");
    }

    #[tokio::test]
    async fn test_registry_list_empty() {
        let registry = SecretsEngineRegistry::new();
        let engines = registry.list_engines();
        assert_eq!(engines.len(), 0);
    }

    #[tokio::test]
    async fn test_registry_metrics_collection() {
        let mut registry = SecretsEngineRegistry::new();
        let engine = MemorySecretsEngine::new();

        registry.register(engine).unwrap();

        let metrics = registry.collect_metrics().await;
        assert!(metrics.is_ok());
        assert!(metrics.unwrap().contains_key("memory"));
    }

    #[tokio::test]
    async fn test_registry_metrics_empty() {
        let registry = SecretsEngineRegistry::new();
        let metrics = registry.collect_metrics().await;
        assert!(metrics.is_ok());
        assert_eq!(metrics.unwrap().len(), 0);
    }
}

#[cfg(test)]
mod secret_lifecycle_tests {
    use secreton_core::services::secrets::Kvv2Engine;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_create_secret() {
        let engine = Kvv2Engine::new();
        let mut data = HashMap::new();
        data.insert("key".to_string(), serde_json::json!("value"));
        let result = engine.write("test/path", data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_read_update_delete() {
        let engine = Kvv2Engine::new();

        // Create
        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String("admin".to_string()));
        data.insert("password".to_string(), Value::String("secret".to_string()));
        let result = engine
            .write("app/config", data, None)
            .await;
        assert!(result.is_ok());

        // Read
        let read_result = engine.read("app/config", None).await;
        assert!(read_result.is_ok());
        let read_data = read_result.unwrap();
        assert_eq!(read_data.data.get("username").unwrap(), "admin");

        // Update
        let mut new_data = HashMap::new();
        new_data.insert("username".to_string(), serde_json::json!("admin"));
        new_data.insert("password".to_string(), serde_json::json!("newsecret"));
        let update_result = engine
            .write("app/config", new_data, None)
            .await;
        assert!(update_result.is_ok());

        // Delete
        assert!(engine.delete("app/config", vec![]).await.is_ok());
        assert!(engine.read("app/config", None).await.is_err());
    }

    #[tokio::test]
    async fn test_create_multiple_secrets() {
        let engine = MemorySecretsEngine::new();

        for i in 0..10 {
            let data = json!({"index": i});
            let result = engine
                .create_secret(&format!("test/{}", i), data, None)
                .await;
            assert!(result.is_ok());
        }

        let secrets = engine.list_secrets("test/").await.unwrap();
        assert!(secrets.len() >= 10);
    }

    #[tokio::test]
    async fn test_update_increments_version() {
        let engine = MemorySecretsEngine::new();

        let data = json!({"key": "value1"});
        let secret = engine
            .create_secret("test/versioning", data, None)
            .await
            .unwrap();
        assert_eq!(secret.metadata.version, 1);

        let data2 = json!({"key": "value2"});
        let updated = engine
            .update_secret("test/versioning", data2, None)
            .await
            .unwrap();
        assert_eq!(updated.metadata.version, 2);

        let data3 = json!({"key": "value3"});
        let updated2 = engine
            .update_secret("test/versioning", data3, None)
            .await
            .unwrap();
        assert_eq!(updated2.metadata.version, 3);
    }

    #[tokio::test]
    async fn test_list_secrets_with_prefix() {
        let engine = MemorySecretsEngine::new();

        // Create multiple secrets
        let data = json!({"key": "value"});
        engine
            .create_secret("app/db/password", data.clone(), None)
            .await
            .unwrap();
        engine
            .create_secret("app/api/key", data.clone(), None)
            .await
            .unwrap();
        engine
            .create_secret("service/token", data, None)
            .await
            .unwrap();

        // List with prefix
        let app_secrets = engine.list_secrets("app/").await.unwrap();
        assert!(app_secrets.len() >= 2);

        let all_secrets = engine.list_secrets("").await.unwrap();
        assert!(all_secrets.len() >= 3);
    }

    #[tokio::test]
    async fn test_list_empty_prefix() {
        let engine = MemorySecretsEngine::new();
        let secrets = engine.list_secrets("nonexistent/").await.unwrap();
        assert_eq!(secrets.len(), 0);
    }

    #[tokio::test]
    async fn test_secret_metadata() {
        let engine = MemorySecretsEngine::new();

        let data = json!({"key": "value"});
        let secret = engine.create_secret("test/path", data, None).await.unwrap();

        assert_eq!(secret.metadata.version, 1);
        assert!(secret.metadata.created_at <= chrono::Utc::now());
        assert!(secret.metadata.updated_at <= chrono::Utc::now());
    }

    #[tokio::test]
    async fn test_secret_with_complex_data() {
        let engine = MemorySecretsEngine::new();

        let data = json!({
            "database": {
                "host": "localhost",
                "port": 5432,
                "username": "admin",
                "password": "secret123"
            },
            "api_keys": ["key1", "key2", "key3"],
            "enabled": true
        });

        let secret = engine
            .create_secret("app/complex", data, None)
            .await
            .unwrap();
        assert_eq!(secret.path, "app/complex");

        let read = engine.read_secret("app/complex").await.unwrap();
        assert!(read.data.get("database").is_some());
        assert!(read.data.get("api_keys").is_some());
    }
}

#[cfg(test)]
mod error_handling_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;

    #[tokio::test]
    async fn test_read_nonexistent_secret() {
        let engine = MemorySecretsEngine::new();
        let result = engine.read_secret("nonexistent/path").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_secret() {
        let engine = MemorySecretsEngine::new();
        let result = engine.delete_secret("nonexistent/path").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_nonexistent_secret() {
        let engine = MemorySecretsEngine::new();
        let data = serde_json::json!({"key": "value"});
        let result = engine.update_secret("nonexistent/path", data, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_double_delete() {
        let engine = MemorySecretsEngine::new();

        let data = serde_json::json!({"key": "value"});
        engine
            .create_secret("test/delete", data, None)
            .await
            .unwrap();

        // First delete should succeed
        assert!(engine.delete_secret("test/delete").await.is_ok());

        // Second delete should fail
        assert!(engine.delete_secret("test/delete").await.is_err());
    }

    #[tokio::test]
    async fn test_read_after_delete() {
        let engine = MemorySecretsEngine::new();

        let data = serde_json::json!({"key": "value"});
        engine
            .create_secret("test/deleted", data, None)
            .await
            .unwrap();
        engine.delete_secret("test/deleted").await.unwrap();

        let result = engine.read_secret("test/deleted").await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod performance_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;
    use std::time::Instant;

    #[tokio::test]
    async fn test_bulk_create_performance() {
        let engine = MemorySecretsEngine::new();
        let start = Instant::now();

        // Create 100 secrets
        for i in 0..100 {
            let data = serde_json::json!({"index": i});
            engine
                .create_secret(&format!("perf/test_{}", i), data, None)
                .await
                .unwrap();
        }

        let duration = start.elapsed();

        // Should complete in reasonable time (< 1 second for memory engine)
        assert!(duration.as_secs() < 1);
    }

    #[tokio::test]
    async fn test_bulk_read_performance() {
        let engine = MemorySecretsEngine::new();

        // Create secrets first
        for i in 0..100 {
            let data = serde_json::json!({"index": i});
            engine
                .create_secret(&format!("perf/test_{}", i), data, None)
                .await
                .unwrap();
        }

        let start = Instant::now();

        // Read 100 secrets
        for i in 0..100 {
            engine
                .read_secret(&format!("perf/test_{}", i))
                .await
                .unwrap();
        }

        let duration = start.elapsed();

        // Should complete in reasonable time
        assert!(duration.as_secs() < 1);
    }

    #[tokio::test]
    async fn test_bulk_update_performance() {
        let engine = MemorySecretsEngine::new();

        // Create secrets first
        for i in 0..50 {
            let data = serde_json::json!({"index": i, "version": 1});
            engine
                .create_secret(&format!("perf/update_{}", i), data, None)
                .await
                .unwrap();
        }

        let start = Instant::now();

        // Update 50 secrets
        for i in 0..50 {
            let data = serde_json::json!({"index": i, "version": 2});
            engine
                .update_secret(&format!("perf/update_{}", i), data, None)
                .await
                .unwrap();
        }

        let duration = start.elapsed();

        // Should complete in reasonable time
        assert!(duration.as_millis() < 500);
    }

    #[tokio::test]
    async fn test_bulk_delete_performance() {
        let engine = MemorySecretsEngine::new();

        // Create secrets first
        for i in 0..100 {
            let data = serde_json::json!({"index": i});
            engine
                .create_secret(&format!("perf/delete_{}", i), data, None)
                .await
                .unwrap();
        }

        let start = Instant::now();

        // Delete 100 secrets
        for i in 0..100 {
            engine
                .delete_secret(&format!("perf/delete_{}", i))
                .await
                .unwrap();
        }

        let duration = start.elapsed();

        // Should complete in reasonable time
        assert!(duration.as_secs() < 1);
    }

    #[tokio::test]
    async fn test_large_secret_performance() {
        let engine = MemorySecretsEngine::new();

        // Create a large secret (1000 key-value pairs)
        let mut large_data = serde_json::Map::new();
        for i in 0..1000 {
            large_data.insert(
                format!("key_{}", i),
                serde_json::json!(format!("value_{}", i)),
            );
        }

        let start = Instant::now();
        let result = engine
            .create_secret("perf/large", serde_json::Value::Object(large_data), None)
            .await;
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(duration.as_millis() < 100);
    }
}

#[cfg(test)]
mod secret_path_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;
    use serde_json::json;

    #[tokio::test]
    async fn test_simple_path() {
        let engine = MemorySecretsEngine::new();
        let data = json!({"key": "value"});
        let result = engine.create_secret("simple", data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nested_path() {
        let engine = MemorySecretsEngine::new();
        let data = json!({"key": "value"});
        let result = engine
            .create_secret("level1/level2/level3/secret", data, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_path_with_special_chars() {
        let engine = MemorySecretsEngine::new();
        let data = json!({"key": "value"});
        let result = engine
            .create_secret("app/db-config/prod_env", data, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_similar_paths() {
        let engine = MemorySecretsEngine::new();
        let data = json!({"key": "value"});

        engine
            .create_secret("app/config", data.clone(), None)
            .await
            .unwrap();
        engine
            .create_secret("app/config/db", data.clone(), None)
            .await
            .unwrap();
        engine
            .create_secret("app/config/api", data, None)
            .await
            .unwrap();

        let secrets = engine.list_secrets("app/config").await.unwrap();
        assert!(secrets.len() >= 3);
    }
}

#[cfg(test)]
mod data_validation_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;
    use serde_json::json;

    #[tokio::test]
    async fn test_empty_data() {
        let engine = MemorySecretsEngine::new();
        let data = json!({});
        let result = engine.create_secret("test/empty", data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_null_values() {
        let engine = MemorySecretsEngine::new();
        let data = json!({"key": null});
        let result = engine.create_secret("test/null", data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_array_data() {
        let engine = MemorySecretsEngine::new();
        let data = json!({"items": [1, 2, 3, 4, 5]});
        let result = engine.create_secret("test/array", data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nested_objects() {
        let engine = MemorySecretsEngine::new();
        let data = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "key": "deep_value"
                    }
                }
            }
        });
        let result = engine.create_secret("test/nested", data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unicode_data() {
        let engine = MemorySecretsEngine::new();
        let data = json!({
            "chinese": "你好世界",
            "japanese": "こんにちは",
            "emoji": "🔐🎉✅"
        });
        let result = engine.create_secret("test/unicode", data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_large_string_value() {
        let engine = MemorySecretsEngine::new();
        let large_string = "x".repeat(10000);
        let data = json!({"large": large_string});
        let result = engine.create_secret("test/large_string", data, None).await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod metrics_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;
    use serde_json::json;

    #[tokio::test]
    async fn test_metrics_after_create() {
        let engine = MemorySecretsEngine::new();

        for i in 0..5 {
            let data = json!({"index": i});
            engine
                .create_secret(&format!("test/{}", i), data, None)
                .await
                .unwrap();
        }

        let metrics = engine.collect_metrics().await.unwrap();
        assert_eq!(metrics.engine_type, "memory");
        assert!(metrics.active_secrets >= 5);
    }

    #[tokio::test]
    async fn test_metrics_after_delete() {
        let engine = MemorySecretsEngine::new();

        // Create 10 secrets
        for i in 0..10 {
            let data = json!({"index": i});
            engine
                .create_secret(&format!("test/{}", i), data, None)
                .await
                .unwrap();
        }

        // Delete 5 secrets
        for i in 0..5 {
            engine.delete_secret(&format!("test/{}", i)).await.unwrap();
        }

        let metrics = engine.collect_metrics().await.unwrap();
        assert!(metrics.active_secrets >= 5);
    }

    #[tokio::test]
    async fn test_metrics_empty_engine() {
        let engine = MemorySecretsEngine::new();
        let metrics = engine.collect_metrics().await.unwrap();
        assert_eq!(metrics.engine_type, "memory");
        assert_eq!(metrics.active_secrets, 0);
    }
}

#[cfg(test)]
mod concurrent_access_tests {
    use secreton_core::services::secrets::Kvv2Engine;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::task;

    #[tokio::test]
    async fn test_concurrent_creates() {
        let engine = Arc::new(Kvv2Engine::new());
        let mut handles = vec![];

        for i in 0..20 {
            let engine_clone: Arc<Kvv2Engine> = Arc::clone(&engine);
            let handle = task::spawn(async move {
                let data = json!({"index": i}).as_object().unwrap().clone();
                engine_clone
                    .write(&format!("concurrent/{}", i), data, None)
                    .await
            });
            handles.push(handle);
        }

        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        let secrets = engine.list("").await;
        assert!(secrets.len() >= 20);
    }

    #[tokio::test]
    async fn test_concurrent_reads() {
        let engine = Arc::new(Kvv2Engine::new());

        // Create a secret first
        let mut data = HashMap::new();
        data.insert("key".to_string(), Value::String("value".to_string()));
        engine
            .write("shared/secret", data, None)
            .await
            .unwrap();

        let mut handles = vec![];
        for _ in 0..50 {
            let engine_clone: Arc<Kvv2Engine> = Arc::clone(&engine);
            let handle =
                task::spawn(async move { engine_clone.read("shared/secret", None).await });
            handles.push(handle);
        }

        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_concurrent_updates() {
        let engine = Arc::new(Kvv2Engine::new());

        // Create initial secret
        let mut data = HashMap::new();
        data.insert("counter".to_string(), Value::Number(0.into()));
        engine
            .write("shared/counter", data, None)
            .await
            .unwrap();

        let mut handles = vec![];
        for i in 0..10 {
            let engine_clone: Arc<Kvv2Engine> = Arc::clone(&engine);
            let handle = task::spawn(async move {
                let mut data = HashMap::new();
                data.insert("counter".to_string(), Value::Number(i.into()));
                engine_clone
                    .write("shared/counter", data, None)
                    .await
            });
            handles.push(handle);
        }

        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        let result = engine.read("shared/counter", None).await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod edge_case_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;
    use serde_json::json;

    #[tokio::test]
    async fn test_very_long_path() {
        let engine = MemorySecretsEngine::new();
        let long_path = "a/".repeat(50) + "secret";
        let data = json!({"key": "value"});
        let result = engine.create_secret(&long_path, data, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_path_with_dots() {
        let engine = MemorySecretsEngine::new();
        let data = json!({"key": "value"});
        let result = engine
            .create_secret("app/../config/secret", data, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rapid_create_delete() {
        let engine = MemorySecretsEngine::new();

        for i in 0..100 {
            let data = json!({"index": i});
            engine
                .create_secret("rapid/test", data, None)
                .await
                .unwrap();
            engine.delete_secret("rapid/test").await.unwrap();
        }

        let result = engine.read_secret("rapid/test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_immediately_after_create() {
        let engine = MemorySecretsEngine::new();

        let data1 = json!({"version": 1});
        engine
            .create_secret("test/immediate", data1, None)
            .await
            .unwrap();

        let data2 = json!({"version": 2});
        let updated = engine
            .update_secret("test/immediate", data2, None)
            .await
            .unwrap();

        assert_eq!(updated.metadata.version, 2);
    }

    #[tokio::test]
    async fn test_special_characters_in_values() {
        let engine = MemorySecretsEngine::new();
        let data = json!({
            "password": "p@$$w0rd!#%&*()[]{}",
            "url": "https://example.com:8080/path?query=value&other=123",
            "json": "{\"nested\": \"value\"}"
        });
        let result = engine.create_secret("test/special", data, None).await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod stress_tests {
    use secreton_core::secrets::engine::memory::MemorySecretsEngine;
    use serde_json::json;

    #[tokio::test]
    async fn test_many_secrets() {
        let engine = MemorySecretsEngine::new();

        // Create 500 secrets
        for i in 0..500 {
            let data = json!({"index": i});
            engine
                .create_secret(&format!("stress/test_{}", i), data, None)
                .await
                .unwrap();
        }

        let secrets = engine.list_secrets("stress/").await.unwrap();
        assert!(secrets.len() >= 500);
    }

    #[tokio::test]
    async fn test_deep_nesting() {
        let engine = MemorySecretsEngine::new();

        let mut nested = json!({"value": "deep"});
        for _ in 0..50 {
            nested = json!({"nested": nested});
        }

        let result = engine.create_secret("test/deep_nest", nested, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_many_keys() {
        let engine = MemorySecretsEngine::new();

        let mut data = serde_json::Map::new();
        for i in 0..1000 {
            data.insert(format!("key_{}", i), json!(format!("value_{}", i)));
        }

        let result = engine
            .create_secret("test/many_keys", json!(data), None)
            .await;
        assert!(result.is_ok());
    }
}
