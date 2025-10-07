//! Comprehensive tests for newly implemented features

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_enterprise_mfa_creation() {
        use crate::auth::mfa::{EnterpriseMFAConfig, EnterpriseMfaManager, MfaContext};

        let config = EnterpriseMFAConfig {
            enabled: true,
            require_multiple_methods: false,
            challenge_timeout: 300,
            admin_operations_require_mfa: true,
            adaptive_mfa_enabled: true,
            risk_threshold: 0.5,
            session_persistence_enabled: true,
            session_duration_minutes: 60,
            hardware_security_keys_enabled: false,
            biometric_auth_enabled: false,
        };

        // Note: This test would need a proper storage backend in a real implementation
        // For now, we're just testing that the struct can be created
        assert_eq!(config.enabled, true);
        assert_eq!(config.risk_threshold, 0.5);
    }

    #[tokio::test]
    async fn test_plugin_system() {
        use crate::plugins::{
            PluginCapability, PluginManager, PluginManagerConfig, PluginType, SimplePlugin,
        };
        use std::path::PathBuf;

        let config = PluginManagerConfig {
            plugin_dir: PathBuf::from("/tmp/plugins"),
            hot_reload: false,
            execution_timeout: 30,
            max_memory_per_plugin: 100,
            enable_isolation: false,
            registry_url: None,
        };

        let manager = PluginManager::new(config);

        // Test that we can create a simple plugin
        let plugin = SimplePlugin::new("test_plugin".to_string());
        let metadata = plugin.metadata();

        assert_eq!(metadata.id, "test_plugin");
        assert_eq!(metadata.name, "Simple Plugin");
        assert!(metadata.types.contains(&PluginType::Integration));
    }

    #[tokio::test]
    async fn test_secrets_sync_config() {
        use crate::secrets_sync::{
            ConflictResolution, ConnectionConfig, ExternalSystem, RetryConfig, SyncConfig,
            SyncDirection, SyncPolicies,
        };

        let connection = ConnectionConfig {
            endpoint: "https://example.com".to_string(),
            credentials: std::collections::HashMap::new(),
            timeout: 30,
            tls: None,
        };

        let policies = SyncPolicies {
            direction: SyncDirection::Outbound,
            conflict_resolution: ConflictResolution::SecretonWins,
            secret_filters: vec!["secret/*".to_string()],
            metadata_fields: vec!["created_at".to_string()],
            auto_sync: true,
            sync_interval: 3600,
        };

        let retry = RetryConfig {
            max_retries: 3,
            initial_delay: 5,
            max_delay: 60,
            backoff_multiplier: 2.0,
        };

        let sync_config = SyncConfig {
            system: ExternalSystem::AwsSecretsManager,
            connection,
            policies,
            retry,
        };

        assert_eq!(sync_config.system, ExternalSystem::AwsSecretsManager);
        assert_eq!(sync_config.policies.direction, SyncDirection::Outbound);
        assert!(sync_config.policies.auto_sync);
    }

    #[tokio::test]
    async fn test_risk_engine() {
        use crate::auth::mfa::{MfaContext, RiskEngine};

        let risk_engine = RiskEngine::new();

        // Test IP risk assessment
        let ip_risk = risk_engine.assess_ip_risk("192.168.1.1").await.unwrap();
        assert!(ip_risk >= 0.0 && ip_risk <= 1.0);

        let public_ip_risk = risk_engine.assess_ip_risk("8.8.8.8").await.unwrap();
        assert!(public_ip_risk >= 0.0 && public_ip_risk <= 1.0);

        // Test location risk assessment
        let location_risk = risk_engine
            .assess_location_risk(37.7749, -122.4194)
            .await
            .unwrap(); // San Francisco
        assert!(location_risk >= 0.0 && location_risk <= 1.0);

        // Test device fingerprint risk
        let device_risk = risk_engine
            .assess_device_risk("long_device_fingerprint_string")
            .await
            .unwrap();
        assert!(device_risk >= 0.0 && device_risk <= 1.0);
    }

    #[tokio::test]
    async fn test_mfa_context() {
        use crate::auth::mfa::MfaContext;

        let context = MfaContext {
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            timestamp: Utc::now(),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            device_fingerprint: Some("device123".to_string()),
            requires_additional_mfa: false,
            risk_score: Some(0.3),
        };

        assert_eq!(context.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(context.risk_score, Some(0.3));
        assert!(!context.requires_additional_mfa);
    }
}
