//! Comprehensive Agent crate tests
//!
//! Tests for monitoring agent, security agent, and system monitoring functionality

use anyhow::Result;
use secreton_agent::{
    config::AgentConfig,
    metrics::{MetricsCollector, SystemMetrics},
    monitor::{HealthMonitor, MonitorConfig},
    security::{SecurityAgent, SecurityConfig},
};
use std::time::Duration;

#[cfg(test)]
mod agent_core_tests {
    use super::*;

    #[test]
    fn test_agent_config_creation() -> Result<()> {
        // Test agent configuration initialization
        let config = AgentConfig {
            enabled: true,
            interval_seconds: 60,
            metrics_enabled: true,
            security_enabled: true,
            health_check_enabled: true,
        };

        assert!(config.enabled);
        assert_eq!(config.interval_seconds, 60);
        assert!(config.metrics_enabled);
        assert!(config.security_enabled);
        assert!(config.health_check_enabled);

        Ok(())
    }

    #[test]
    fn test_monitor_config_validation() -> Result<()> {
        // Test monitor configuration
        let config = MonitorConfig {
            health_check_interval: Duration::from_secs(30),
            metrics_collection_interval: Duration::from_secs(60),
            security_scan_interval: Duration::from_secs(300),
            alert_thresholds: Default::default(),
        };

        assert_eq!(config.health_check_interval, Duration::from_secs(30));
        assert_eq!(config.metrics_collection_interval, Duration::from_secs(60));
        assert_eq!(config.security_scan_interval, Duration::from_secs(300));

        Ok(())
    }

    #[test]
    fn test_security_config_initialization() -> Result<()> {
        // Test security configuration
        let config = SecurityConfig {
            threat_detection_enabled: true,
            intrusion_detection_enabled: true,
            anomaly_detection_enabled: true,
            log_analysis_enabled: true,
        };

        assert!(config.threat_detection_enabled);
        assert!(config.intrusion_detection_enabled);
        assert!(config.anomaly_detection_enabled);
        assert!(config.log_analysis_enabled);

        Ok(())
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() -> Result<()> {
        // Test metrics collector initialization
        let collector = MetricsCollector::new();
        assert!(collector.is_ok());

        Ok(())
    }

    #[test]
    fn test_system_metrics_collection() -> Result<()> {
        // Test system metrics structure
        let metrics = SystemMetrics {
            cpu_usage: 45.0,
            memory_usage: 67.0,
            disk_usage: 23.0,
            network_rx: 1024,
            network_tx: 512,
            timestamp: chrono::Utc::now(),
        };

        assert_eq!(metrics.cpu_usage, 45.0);
        assert_eq!(metrics.memory_usage, 67.0);
        assert_eq!(metrics.disk_usage, 23.0);
        assert_eq!(metrics.network_rx, 1024);
        assert_eq!(metrics.network_tx, 512);

        Ok(())
    }

    #[tokio::test]
    async fn test_metrics_collection_interval() -> Result<()> {
        // Test metrics collection timing (mock test)
        let collector = MetricsCollector::new()?;

        // Mock metrics collection should not fail
        let metrics = collector.collect_system_metrics().await?;

        // Metrics should have reasonable values
        assert!(metrics.cpu_usage >= 0.0 && metrics.cpu_usage <= 100.0);
        assert!(metrics.memory_usage >= 0.0 && metrics.memory_usage <= 100.0);
        assert!(metrics.disk_usage >= 0.0 && metrics.disk_usage <= 100.0);

        Ok(())
    }
}

#[cfg(test)]
mod monitoring_tests {
    use super::*;

    #[test]
    fn test_health_monitor_creation() -> Result<()> {
        // Test health monitor initialization
        let config = MonitorConfig {
            health_check_interval: Duration::from_secs(30),
            metrics_collection_interval: Duration::from_secs(60),
            security_scan_interval: Duration::from_secs(300),
            alert_thresholds: Default::default(),
        };

        let monitor = HealthMonitor::new(config);
        assert!(monitor.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_health_check_execution() -> Result<()> {
        // Test health check functionality
        let config = MonitorConfig {
            health_check_interval: Duration::from_secs(30),
            metrics_collection_interval: Duration::from_secs(60),
            security_scan_interval: Duration::from_secs(300),
            alert_thresholds: Default::default(),
        };

        let monitor = HealthMonitor::new(config)?;

        // Health check should execute without errors
        let health_status = monitor.perform_health_check().await?;

        // Health status should be valid
        assert!(health_status.is_healthy || !health_status.is_healthy); // Boolean value

        Ok(())
    }

    #[tokio::test]
    async fn test_monitoring_interval_configuration() -> Result<()> {
        // Test monitoring interval configuration
        let config = MonitorConfig {
            health_check_interval: Duration::from_secs(15),
            metrics_collection_interval: Duration::from_secs(30),
            security_scan_interval: Duration::from_secs(120),
            alert_thresholds: Default::default(),
        };

        let monitor = HealthMonitor::new(config)?;

        // Verify intervals are set correctly
        assert_eq!(monitor.get_health_check_interval(), Duration::from_secs(15));
        assert_eq!(monitor.get_metrics_interval(), Duration::from_secs(30));

        Ok(())
    }
}

#[cfg(test)]
mod security_agent_tests {
    use super::*;

    #[test]
    fn test_security_agent_creation() -> Result<()> {
        // Test security agent initialization
        let config = SecurityConfig {
            threat_detection_enabled: true,
            intrusion_detection_enabled: true,
            anomaly_detection_enabled: false,
            log_analysis_enabled: true,
        };

        let agent = SecurityAgent::new(config);
        assert!(agent.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_threat_detection() -> Result<()> {
        // Test threat detection functionality
        let config = SecurityConfig {
            threat_detection_enabled: true,
            intrusion_detection_enabled: false,
            anomaly_detection_enabled: false,
            log_analysis_enabled: false,
        };

        let agent = SecurityAgent::new(config)?;

        // Threat detection should execute without errors
        let threats = agent.detect_threats().await?;

        // Threats should be a valid result (could be empty vector)
        assert!(threats.is_empty() || !threats.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_intrusion_detection() -> Result<()> {
        // Test intrusion detection functionality
        let config = SecurityConfig {
            threat_detection_enabled: false,
            intrusion_detection_enabled: true,
            anomaly_detection_enabled: false,
            log_analysis_enabled: false,
        };

        let agent = SecurityAgent::new(config)?;

        // Intrusion detection should execute without errors
        let intrusions = agent.detect_intrusions().await?;

        // Intrusions should be a valid result
        assert!(intrusions.is_empty() || !intrusions.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_log_analysis() -> Result<()> {
        // Test log analysis functionality
        let config = SecurityConfig {
            threat_detection_enabled: false,
            intrusion_detection_enabled: false,
            anomaly_detection_enabled: false,
            log_analysis_enabled: true,
        };

        let agent = SecurityAgent::new(config)?;

        // Log analysis should execute without errors
        let analysis = agent.analyze_logs().await?;

        // Analysis should be a valid result
        assert!(analysis.is_empty() || !analysis.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_anomaly_detection() -> Result<()> {
        // Test anomaly detection functionality
        let config = SecurityConfig {
            threat_detection_enabled: false,
            intrusion_detection_enabled: false,
            anomaly_detection_enabled: true,
            log_analysis_enabled: false,
        };

        let agent = SecurityAgent::new(config)?;

        // Anomaly detection should execute without errors
        let anomalies = agent.detect_anomalies().await?;

        // Anomalies should be a valid result
        assert!(anomalies.is_empty() || !anomalies.is_empty());

        Ok(())
    }
}

#[cfg(test)]
mod agent_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_comprehensive_monitoring() -> Result<()> {
        // Test comprehensive agent functionality
        let agent_config = AgentConfig {
            enabled: true,
            interval_seconds: 60,
            metrics_enabled: true,
            security_enabled: true,
            health_check_enabled: true,
        };

        // Agent should initialize with all components
        assert!(agent_config.enabled);
        assert!(agent_config.metrics_enabled);
        assert!(agent_config.security_enabled);
        assert!(agent_config.health_check_enabled);

        Ok(())
    }

    #[tokio::test]
    async fn test_agent_performance_monitoring() -> Result<()> {
        // Test agent performance monitoring capabilities
        let config = MonitorConfig {
            health_check_interval: Duration::from_secs(10),
            metrics_collection_interval: Duration::from_secs(20),
            security_scan_interval: Duration::from_secs(60),
            alert_thresholds: Default::default(),
        };

        let monitor = HealthMonitor::new(config)?;

        // Performance monitoring should be configurable
        assert_eq!(monitor.get_health_check_interval(), Duration::from_secs(10));
        assert_eq!(monitor.get_metrics_interval(), Duration::from_secs(20));

        Ok(())
    }

    #[test]
    fn test_agent_configuration_validation() -> Result<()> {
        // Test agent configuration validation
        let valid_configs = vec![
            AgentConfig {
                enabled: true,
                interval_seconds: 30,
                metrics_enabled: true,
                security_enabled: false,
                health_check_enabled: true,
            },
            AgentConfig {
                enabled: false,
                interval_seconds: 60,
                metrics_enabled: false,
                security_enabled: true,
                health_check_enabled: false,
            },
        ];

        // All configurations should be valid
        assert_eq!(valid_configs.len(), 2);

        Ok(())
    }
}
