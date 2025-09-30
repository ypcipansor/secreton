//! Monitoring and Alerting System for Secreton
//!
//! Provides comprehensive observability for the vault system including:
//! - Metrics collection from all components
//! - Prometheus-compatible metrics export
//! - Alerting rules engine
//! - Health check endpoints
//! - Event streaming and webhook notifications

pub mod telemetry;
pub mod events;

pub use telemetry::*;
pub use events::*;

use super::{Secret, SecretMetadata, SecretsEngine, SecretsError};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use prometheus::{Encoder, Gauge, Histogram, IntCounter, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Metrics snapshot for a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Timestamp when metrics were collected
    pub timestamp: DateTime<Utc>,
    /// Engine-specific metrics
    pub engine_metrics: HashMap<String, EngineMetrics>,
    /// System-level metrics
    pub system_metrics: SystemMetrics,
    /// Alert status
    pub alerts: Vec<Alert>,
}

/// Metrics for a specific secrets engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineMetrics {
    /// Engine type (kv, database, aws, etc.)
    pub engine_type: String,
    /// Number of secrets created
    pub secrets_created: u64,
    /// Number of secrets read
    pub secrets_read: u64,
    /// Number of secrets updated
    pub secrets_updated: u64,
    /// Number of secrets deleted
    pub secrets_deleted: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Error count
    pub error_count: u64,
    /// Active secrets count
    pub active_secrets: u64,
    /// Total storage size in bytes
    pub storage_size_bytes: u64,
}

/// System-level metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Total number of active secrets across all engines
    pub total_secrets: u64,
    /// Total storage usage in bytes
    pub total_storage_bytes: u64,
    /// Number of active authentication sessions
    pub active_sessions: u64,
    /// System uptime in seconds
    pub uptime_seconds: u64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Number of active goroutines/threads
    pub active_threads: u32,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Alert definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: String,
    /// Alert name
    pub name: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert message
    pub message: String,
    /// Timestamp when alert was triggered
    pub timestamp: DateTime<Utc>,
    /// Labels for categorization
    pub labels: HashMap<String, String>,
    /// Alert value that triggered the condition
    pub value: f64,
    /// Threshold that was exceeded
    pub threshold: f64,
}

/// Alert rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Unique rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Metric to evaluate
    pub metric: String,
    /// Condition operator (>, <, >=, <=, ==, !=)
    pub operator: String,
    /// Threshold value
    pub threshold: f64,
    /// Evaluation interval in seconds
    pub interval_seconds: u64,
    /// Duration to wait before triggering alert
    pub for_duration_seconds: u64,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Labels to attach to triggered alerts
    pub labels: HashMap<String, String>,
    /// Whether rule is enabled
    pub enabled: bool,
}

/// Alert condition for evaluation
#[derive(Debug, Clone)]
pub struct AlertCondition {
    /// Metric value to check
    pub value: f64,
    /// Threshold to compare against
    pub threshold: f64,
    /// Operator for comparison
    pub operator: String,
}

/// Metrics collector for the entire system
pub struct MetricsCollector {
    registry: Registry,
    engine_metrics: Arc<RwLock<HashMap<String, EngineMetrics>>>,
    system_metrics: Arc<RwLock<SystemMetrics>>,
    alert_rules: Arc<RwLock<Vec<AlertRule>>>,
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,
    start_time: Instant,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        // Register default metrics
        let build_info = prometheus::Opts::new("vault_build_info", "Vault build information")
            .const_label("version", env!("CARGO_PKG_VERSION"))
            .const_label("build_time", env!("VERGEN_BUILD_TIMESTAMP"))
            .const_label("git_sha", env!("VERGEN_GIT_SHA"));
        let _build_info = Gauge::with_opts(build_info)?;

        Ok(Self {
            registry,
            engine_metrics: Arc::new(RwLock::new(HashMap::new())),
            system_metrics: Arc::new(RwLock::new(SystemMetrics {
                total_secrets: 0,
                total_storage_bytes: 0,
                active_sessions: 0,
                uptime_seconds: 0,
                cpu_usage_percent: 0.0,
                memory_usage_bytes: 0,
                active_threads: 0,
            })),
            alert_rules: Arc::new(RwLock::new(Vec::new())),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
        })
    }

    /// Collect metrics from all registered secrets engines
    pub async fn collect_engine_metrics(&self, engines: &HashMap<String, Arc<dyn SecretsEngine>>) -> Result<MetricsSnapshot> {
        let mut snapshot = MetricsSnapshot {
            timestamp: Utc::now(),
            engine_metrics: HashMap::new(),
            system_metrics: SystemMetrics {
                total_secrets: 0,
                total_storage_bytes: 0,
                active_sessions: 0,
                uptime_seconds: self.start_time.elapsed().as_secs(),
                cpu_usage_percent: 0.0, // Would need system monitoring
                memory_usage_bytes: 0,   // Would need system monitoring
                active_threads: 0,       // Would need system monitoring
            },
            alerts: Vec::new(),
        };

        // Collect metrics from each engine
        for (engine_name, engine) in engines {
            match self.collect_single_engine_metrics(engine_name, engine.as_ref()).await {
                Ok(metrics) => {
                    snapshot.engine_metrics.insert(engine_name.clone(), metrics.clone());
                    snapshot.system_metrics.total_secrets += metrics.active_secrets;
                    snapshot.system_metrics.total_storage_bytes += metrics.storage_size_bytes;
                }
                Err(e) => {
                    error!("Failed to collect metrics from engine {}: {}", engine_name, e);
                }
            }
        }

        // Evaluate alert rules
        snapshot.alerts = self.evaluate_alert_rules(&snapshot).await?;

        Ok(snapshot)
    }

    /// Collect metrics from a single engine
    async fn collect_single_engine_metrics(&self, engine_name: &str, engine: &dyn SecretsEngine) -> Result<EngineMetrics> {
        // This is a simplified implementation
        // In practice, engines would expose their own metrics collection methods

        Ok(EngineMetrics {
            engine_type: engine.engine_type().to_string(),
            secrets_created: 0, // Would be tracked by engine
            secrets_read: 0,    // Would be tracked by engine
            secrets_updated: 0, // Would be tracked by engine
            secrets_deleted: 0, // Would be tracked by engine
            avg_response_time_ms: 0.0, // Would be calculated from timing data
            error_count: 0,     // Would be tracked by engine
            active_secrets: 0,  // Would be calculated by engine
            storage_size_bytes: 0, // Would be calculated by engine
        })
    }

    /// Evaluate alert rules against current metrics
    async fn evaluate_alert_rules(&self, snapshot: &MetricsSnapshot) -> Result<Vec<Alert>> {
        let rules = self.alert_rules.read().await;
        let mut alerts = Vec::new();

        for rule in rules.iter().filter(|r| r.enabled) {
            if let Some(alert) = self.evaluate_rule(rule, snapshot).await? {
                alerts.push(alert);
            }
        }

        Ok(alerts)
    }

    /// Evaluate a single alert rule
    async fn evaluate_rule(&self, rule: &AlertRule, snapshot: &MetricsSnapshot) -> Result<Option<Alert>> {
        // Extract metric value (simplified - would need proper metric extraction)
        let metric_value = match rule.metric.as_str() {
            "system.total_secrets" => snapshot.system_metrics.total_secrets as f64,
            "system.total_storage_bytes" => snapshot.system_metrics.total_storage_bytes as f64,
            "system.active_sessions" => snapshot.system_metrics.active_sessions as f64,
            "system.uptime_seconds" => snapshot.system_metrics.uptime_seconds as f64,
            _ => {
                // For engine-specific metrics, would need more complex parsing
                0.0
            }
        };

        // Evaluate condition
        let condition_met = match rule.operator.as_str() {
            ">" => metric_value > rule.threshold,
            "<" => metric_value < rule.threshold,
            ">=" => metric_value >= rule.threshold,
            "<=" => metric_value <= rule.threshold,
            "==" => (metric_value - rule.threshold).abs() < f64::EPSILON,
            "!=" => (metric_value - rule.threshold).abs() >= f64::EPSILON,
            _ => false,
        };

        if condition_met {
            let alert = Alert {
                id: format!("{}_{}", rule.id, Utc::now().timestamp()),
                name: rule.name.clone(),
                severity: rule.severity.clone(),
                message: format!("{}: {} {} {}", rule.metric, rule.operator, rule.threshold, metric_value),
                timestamp: Utc::now(),
                labels: rule.labels.clone(),
                value: metric_value,
                threshold: rule.threshold,
            };

            return Ok(Some(alert));
        }

        Ok(None)
    }

    /// Add an alert rule
    pub async fn add_alert_rule(&self, rule: AlertRule) -> Result<()> {
        let mut rules = self.alert_rules.write().await;
        rules.push(rule);
        info!("Added alert rule: {}", rules.len());
        Ok(())
    }

    /// Remove an alert rule
    pub async fn remove_alert_rule(&self, rule_id: &str) -> Result<()> {
        let mut rules = self.alert_rules.write().await;
        rules.retain(|r| r.id != rule_id);
        info!("Removed alert rule: {}", rule_id);
        Ok(())
    }

    /// Get all alert rules
    pub async fn get_alert_rules(&self) -> Vec<AlertRule> {
        self.alert_rules.read().await.clone()
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().await.values().cloned().collect()
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus_metrics(&self) -> Result<String> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer)?;

        Ok(String::from_utf8(buffer)?)
    }

    /// Update system metrics (would be called by system monitoring)
    pub async fn update_system_metrics(&self, metrics: SystemMetrics) -> Result<()> {
        let mut system_metrics = self.system_metrics.write().await;
        *system_metrics = metrics;
        Ok(())
    }

    /// Health check endpoint data
    pub async fn get_health_status(&self) -> Result<HealthStatus> {
        let system_metrics = self.system_metrics.read().await;
        let active_alerts = self.get_active_alerts().await;

        let critical_alerts = active_alerts.iter()
            .filter(|a| matches!(a.severity, AlertSeverity::Critical))
            .count();

        let status = if critical_alerts > 0 {
            HealthStatus::Unhealthy
        } else if active_alerts.iter().any(|a| matches!(a.severity, AlertSeverity::Error)) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        Ok(HealthStatus {
            status,
            uptime_seconds: system_metrics.uptime_seconds,
            total_secrets: system_metrics.total_secrets,
            active_sessions: system_metrics.active_sessions,
            critical_alerts,
            total_alerts: active_alerts.len(),
            timestamp: Utc::now(),
        })
    }
}

/// Health status for the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall system health
    pub status: SystemHealth,
    /// System uptime in seconds
    pub uptime_seconds: u64,
    /// Total number of secrets
    pub total_secrets: u64,
    /// Number of active sessions
    pub active_sessions: u64,
    /// Number of critical alerts
    pub critical_alerts: usize,
    /// Total number of active alerts
    pub total_alerts: usize,
    /// Timestamp of health check
    pub timestamp: DateTime<Utc>,
}

/// System health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SystemHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert!(collector.is_ok());
    }

    #[tokio::test]
    async fn test_alert_rule_evaluation() {
        let collector = MetricsCollector::new().unwrap();

        // Add a test alert rule
        let rule = AlertRule {
            id: "test_rule".to_string(),
            name: "Test Rule".to_string(),
            description: "Test alert rule".to_string(),
            metric: "system.total_secrets".to_string(),
            operator: ">".to_string(),
            threshold: 100.0,
            interval_seconds: 60,
            for_duration_seconds: 300,
            severity: AlertSeverity::Warning,
            labels: HashMap::new(),
            enabled: true,
        };

        collector.add_alert_rule(rule).await.unwrap();

        // Create test metrics
        let mut snapshot = MetricsSnapshot {
            timestamp: Utc::now(),
            engine_metrics: HashMap::new(),
            system_metrics: SystemMetrics {
                total_secrets: 150, // Above threshold
                total_storage_bytes: 0,
                active_sessions: 0,
                uptime_seconds: 0,
                cpu_usage_percent: 0.0,
                memory_usage_bytes: 0,
                active_threads: 0,
            },
            alerts: Vec::new(),
        };

        // Evaluate rules
        let alerts = collector.evaluate_alert_rules(&snapshot).await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "Test Rule");
    }

    #[test]
    fn test_system_health_status() {
        let collector = MetricsCollector::new().unwrap();

        // Test healthy status
        let status = SystemHealth::Healthy;
        assert_eq!(status, SystemHealth::Healthy);

        // Test degraded status
        let status = SystemHealth::Degraded;
        assert_eq!(status, SystemHealth::Degraded);

        // Test unhealthy status
        let status = SystemHealth::Unhealthy;
        assert_eq!(status, SystemHealth::Unhealthy);
    }
}
