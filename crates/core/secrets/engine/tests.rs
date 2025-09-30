// Comprehensive tests for all secrets engines

#[cfg(test)]
mod consul_tests {
    use crate::secrets::engine::consul::{ConsulConfig, ConsulEngine};
    use crate::secrets::engine::SecretsEngine;

    #[tokio::test]
    async fn test_consul_engine_creation() {
        let config = ConsulConfig::default();
        let engine = ConsulEngine::new(config).await;
        assert!(engine.is_ok());
        assert_eq!(engine.unwrap().engine_type(), "consul");
    }

    #[tokio::test]
    async fn test_consul_config_validation() {
        let mut config = ConsulConfig::default();
        config.address = "http://localhost:8500".to_string();
        config.default_ttl = 7200;
        
        let engine = ConsulEngine::new(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_consul_metrics_collection() {
        let config = ConsulConfig::default();
        let engine = ConsulEngine::new(config).await.unwrap();
        let metrics = engine.collect_metrics().await;
        assert!(metrics.is_ok());
        assert_eq!(metrics.unwrap().engine_type, "consul");
    }
}

#[cfg(test)]
mod nomad_tests {
    use crate::secrets::engine::nomad::{NomadConfig, NomadEngine};
    use crate::secrets::engine::SecretsEngine;

    #[tokio::test]
    async fn test_nomad_engine_creation() {
        let config = NomadConfig::default();
        let engine = NomadEngine::new(config).await;
        assert!(engine.is_ok());
        assert_eq!(engine.unwrap().engine_type(), "nomad");
    }

    #[tokio::test]
    async fn test_nomad_config_validation() {
        let mut config = NomadConfig::default();
        config.address = "http://localhost:4646".to_string();
        config.default_ttl = 3600;
        config.max_ttl = 86400;
        
        let engine = NomadEngine::new(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_nomad_metrics_collection() {
        let config = NomadConfig::default();
        let engine = NomadEngine::new(config).await.unwrap();
        let metrics = engine.collect_metrics().await;
        assert!(metrics.is_ok());
        assert_eq!(metrics.unwrap().engine_type, "nomad");
    }
}

#[cfg(test)]
mod ad_tests {
    use crate::secrets::engine::ad::{ActiveDirectoryConfig, ActiveDirectoryEngine};
    use crate::secrets::engine::SecretsEngine;

    #[test]
    fn test_ad_engine_creation() {
        let config = ActiveDirectoryConfig::default();
        let engine = ActiveDirectoryEngine::new(config);
        assert_eq!(engine.engine_type(), "ad");
    }

    #[test]
    fn test_ad_password_generation() {
        let config = ActiveDirectoryConfig::default();
        let engine = ActiveDirectoryEngine::new(config);
        let password = engine.generate_password();
        assert_eq!(password.len(), 32);
        assert!(password.chars().all(|c| c.is_ascii()));
    }

    #[test]
    fn test_ad_config_validation() {
        let mut config = ActiveDirectoryConfig::default();
        config.password_length = 64;
        config.rotation_period = 43200; // 12 hours
        
        let engine = ActiveDirectoryEngine::new(config);
        assert_eq!(engine.engine_type(), "ad");
    }

    #[tokio::test]
    async fn test_ad_metrics_collection() {
        let config = ActiveDirectoryConfig::default();
        let engine = ActiveDirectoryEngine::new(config);
        let metrics = engine.collect_metrics().await;
        assert!(metrics.is_ok());
        assert_eq!(metrics.unwrap().engine_type, "ad");
    }
}

#[cfg(test)]
mod mongodbatlas_tests {
    use crate::secrets::engine::mongodbatlas::{MongoDbAtlasConfig, MongoDbAtlasEngine};
    use crate::secrets::engine::SecretsEngine;

    #[tokio::test]
    async fn test_mongodbatlas_engine_creation() {
        let config = MongoDbAtlasConfig::default();
        let engine = MongoDbAtlasEngine::new(config).await;
        assert!(engine.is_ok());
        assert_eq!(engine.unwrap().engine_type(), "mongodbatlas");
    }

    #[tokio::test]
    async fn test_mongodbatlas_config_validation() {
        let mut config = MongoDbAtlasConfig::default();
        config.public_key = "test-public-key".to_string();
        config.private_key = "test-private-key".to_string();
        config.project_id = "test-project-id".to_string();
        
        let engine = MongoDbAtlasEngine::new(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_mongodbatlas_metrics_collection() {
        let config = MongoDbAtlasConfig::default();
        let engine = MongoDbAtlasEngine::new(config).await.unwrap();
        let metrics = engine.collect_metrics().await;
        assert!(metrics.is_ok());
        assert_eq!(metrics.unwrap().engine_type, "mongodbatlas");
    }
}

#[cfg(test)]
mod engine_integration_tests {
    use crate::secrets::engine::SecretsEngine;
    use crate::secrets::engine::memory::MemorySecretsEngine;
    use serde_json::json;

    #[tokio::test]
    async fn test_memory_engine_full_lifecycle() {
        let engine = MemorySecretsEngine::new();
        
        // Create secret
        let data = json!({"key": "value", "password": "secret123"});
        let secret = engine.create_secret("test/path", data.clone(), None).await;
        assert!(secret.is_ok());
        
        // Read secret
        let read_result = engine.read_secret("test/path").await;
        assert!(read_result.is_ok());
        
        // Update secret
        let new_data = json!({"key": "new_value"});
        let update_result = engine.update_secret("test/path", new_data, None).await;
        assert!(update_result.is_ok());
        
        // List secrets
        let list_result = engine.list_secrets("test/").await;
        assert!(list_result.is_ok());
        
        // Delete secret
        let delete_result = engine.delete_secret("test/path").await;
        assert!(delete_result.is_ok());
    }

    #[tokio::test]
    async fn test_memory_engine_metrics() {
        let engine = MemorySecretsEngine::new();
        
        // Create multiple secrets
        for i in 0..5 {
            let data = json!({"index": i});
            let _ = engine.create_secret(&format!("test/{}", i), data, None).await;
        }
        
        // Collect metrics
        let metrics = engine.collect_metrics().await;
        assert!(metrics.is_ok());
        let m = metrics.unwrap();
        assert_eq!(m.engine_type, "memory");
        assert!(m.active_secrets >= 5);
    }
}
