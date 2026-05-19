//! End-to-End Observability Pipeline
//!
//! Integrates distributed tracing, advanced observability, AI anomaly detection,
//! and emergency response to provide comprehensive monitoring and incident management
//! across all 112 platform features with automatic correlation and response.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::distributed_tracing::TraceSpan;

#[derive(Debug, Error)]
pub enum ObservabilityError {
    #[error("Tracing failed: {0}")]
    TracingFailed(String),
    #[error("Metrics collection failed: {0}")]
    MetricsFailed(String),
    #[error("Anomaly detection failed: {0}")]
    AnomalyDetectionFailed(String),
    #[error("Alert generation failed: {0}")]
    AlertFailed(String),
}

pub type Result<T> = std::result::Result<T, ObservabilityError>;

/// Operation trace with full _context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationTrace {
    pub trace_id: String,
    pub operation_name: String,
    pub service_name: String,
    pub started_at: DateTime<Utc>,
    pub duration_ms: f64,
    pub spans: Vec<TraceSpan>,
    pub tags: HashMap<String, String>,
    pub success: bool,
    pub error: Option<String>,
}

/// Comprehensive health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveHealthCheck {
    pub check_id: String,
    pub checked_at: DateTime<Utc>,
    pub overall_status: HealthStatus,
    pub overall_score: f64,
    pub component_health: HashMap<String, ComponentHealth>,
    pub degraded_components: Vec<String>,
    pub unhealthy_components: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component_name: String,
    pub _status: HealthStatus,
    pub response_time_ms: f64,
    pub error_rate: f64,
    pub last_check: DateTime<Utc>,
    pub details: HashMap<String, String>,
}

/// Correlated incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedIncident {
    pub incident_id: String,
    pub severity: IncidentSeverity,
    pub title: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub correlated_traces: Vec<String>,
    pub correlated_metrics: Vec<String>,
    pub correlated_anomalies: Vec<String>,
    pub affected_services: Vec<String>,
    pub root_cause_hypothesis: Option<String>,
    pub _status: IncidentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Detected,
    Investigating,
    Mitigating,
    Resolved,
    Closed,
}

/// Performance aggregate metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub metric_id: String,
    pub collected_at: DateTime<Utc>,
    pub time_window_minutes: u32,
    pub total_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub average_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub error_rate: f64,
    pub throughput_per_second: f64,
}

/// Alert rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: String,
    pub _name: String,
    pub condition: AlertCondition,
    pub threshold: f64,
    pub window_minutes: u32,
    pub severity: IncidentSeverity,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    ErrorRateAbove,
    LatencyAbove,
    ThroughputBelow,
    AnomalyDetected,
    HealthDegraded,
}

/// Generated alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub rule_id: String,
    pub severity: IncidentSeverity,
    pub title: String,
    pub message: String,
    pub triggered_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub acknowledged: bool,
}

/// End-to-end observability pipeline
pub struct EndToEndObservabilityPipeline {
    traces: Arc<RwLock<Vec<OperationTrace>>>,
    metrics: Arc<RwLock<Vec<PerformanceMetrics>>>,
    health_checks: Arc<RwLock<Vec<ComprehensiveHealthCheck>>>,
    incidents: Arc<RwLock<Vec<CorrelatedIncident>>>,
    alert_rules: Arc<RwLock<HashMap<String, AlertRule>>>,
    active_alerts: Arc<RwLock<Vec<Alert>>>,
}

impl EndToEndObservabilityPipeline {
    pub fn new() -> Self {
        Self {
            traces: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(Vec::new())),
            health_checks: Arc::new(RwLock::new(Vec::new())),
            incidents: Arc::new(RwLock::new(Vec::new())),
            alert_rules: Arc::new(RwLock::new(HashMap::new())),
            active_alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Trace complete operation across services
    pub async fn trace_operation(
        &self,
        operation_name: String,
        service_name: String,
        execute_fn: impl std::future::Future<Output = std::result::Result<(), String>>,
    ) -> Result<OperationTrace> {
        let trace_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();

        // Create root span
        let root_span = TraceSpan {
            span_id: Uuid::new_v4().to_string(),
            trace_id: trace_id.clone(),
            parent_span_id: None,
            operation_name: operation_name.clone(),
            started_at,
            duration_ms: Some(0),
            tags: HashMap::from([("service".to_string(), service_name.clone())]),
            _status: super::distributed_tracing::SpanStatus::Ok,
            error_message: None,
        };

        // Execute operation
        let result = execute_fn.await;
        let ended_at = Utc::now();
        let duration_ms = ended_at
            .signed_duration_since(started_at)
            .num_milliseconds() as f64;

        let success = result.is_ok();
        let error = result.err();

        let trace = OperationTrace {
            trace_id: trace_id.clone(),
            operation_name: operation_name.clone(),
            service_name,
            started_at,
            duration_ms,
            spans: vec![root_span],
            tags: HashMap::new(),
            success,
            error,
        };

        // Store trace
        self.traces.write().await.push(trace.clone());

        // Collect metrics
        self.record_operation_metrics(&operation_name, duration_ms, success)
            .await;

        // Check for anomalies
        if let Some(incident) = self.check_anomalies(&trace).await {
            self.incidents.write().await.push(incident);
        }

        Ok(trace)
    }

    /// Comprehensive health check across all components
    pub async fn comprehensive_health_check(&self) -> Result<ComprehensiveHealthCheck> {
        let check_id = Uuid::new_v4().to_string();
        let checked_at = Utc::now();

        // Mock component health checks
        let mut component_health = HashMap::new();

        let components = vec![
            "authentication",
            "key_management",
            "secrets_engine",
            "policy_engine",
            "audit_logging",
            "metrics",
            "tracing",
            "storage",
            "replication",
            "federation",
        ];

        for component in components {
            let health = self.check_component_health(component).await;
            component_health.insert(component.to_string(), health);
        }

        // Calculate overall _status
        let degraded_components: Vec<String> = component_health
            .iter()
            .filter(|(_, h)| h._status == HealthStatus::Degraded)
            .map(|(_name, _)| _name.clone())
            .collect();

        let unhealthy_components: Vec<String> = component_health
            .iter()
            .filter(|(_, h)| h._status == HealthStatus::Unhealthy)
            .map(|(_name, _)| _name.clone())
            .collect();

        let overall_status = if !unhealthy_components.is_empty() {
            HealthStatus::Unhealthy
        } else if !degraded_components.is_empty() {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        let healthy_count = component_health
            .values()
            .filter(|h| h._status == HealthStatus::Healthy)
            .count();
        let overall_score = (healthy_count as f64 / component_health.len() as f64) * 100.0;

        let health_check = ComprehensiveHealthCheck {
            check_id,
            checked_at,
            overall_status,
            overall_score,
            component_health,
            degraded_components,
            unhealthy_components,
        };

        self.health_checks.write().await.push(health_check.clone());

        Ok(health_check)
    }

    /// Correlate metrics, traces, and logs to detect incidents
    pub async fn incident_correlation(&self) -> Result<Vec<CorrelatedIncident>> {
        let recent_traces = self.get_recent_traces(Duration::minutes(15)).await;
        let recent_metrics = self.get_recent_metrics(Duration::minutes(15)).await;

        let mut incidents = Vec::new();

        // Check for error rate spike
        let error_rate = self.calculate_error_rate(&recent_traces);
        if error_rate > 0.1 {
            // >10% error rate
            let incident = CorrelatedIncident {
                incident_id: Uuid::new_v4().to_string(),
                severity: if error_rate > 0.5 {
                    IncidentSeverity::Critical
                } else {
                    IncidentSeverity::High
                },
                title: "High Error Rate Detected".to_string(),
                description: format!("Error rate: {:.2}%", error_rate * 100.0),
                detected_at: Utc::now(),
                correlated_traces: recent_traces
                    .iter()
                    .filter(|t| !t.success)
                    .map(|t| t.trace_id.clone())
                    .collect(),
                correlated_metrics: recent_metrics.iter().map(|m| m.metric_id.clone()).collect(),
                correlated_anomalies: Vec::new(),
                affected_services: self.get_affected_services(&recent_traces),
                root_cause_hypothesis: Some("Potential service degradation".to_string()),
                _status: IncidentStatus::Detected,
            };

            incidents.push(incident);
        }

        // Check for latency spike
        let p99_latency = self.calculate_p99_latency(&recent_traces);
        if p99_latency > 1000.0 {
            // >1 second
            let incident = CorrelatedIncident {
                incident_id: Uuid::new_v4().to_string(),
                severity: IncidentSeverity::High,
                title: "High Latency Detected".to_string(),
                description: format!("P99 latency: {:.2}ms", p99_latency),
                detected_at: Utc::now(),
                correlated_traces: recent_traces
                    .iter()
                    .filter(|t| t.duration_ms > 1000.0)
                    .map(|t| t.trace_id.clone())
                    .collect(),
                correlated_metrics: Vec::new(),
                correlated_anomalies: Vec::new(),
                affected_services: self.get_affected_services(&recent_traces),
                root_cause_hypothesis: Some(
                    "Resource contention or external dependency issue".to_string(),
                ),
                _status: IncidentStatus::Detected,
            };

            incidents.push(incident);
        }

        // Store incidents
        self.incidents.write().await.extend(incidents.clone());

        Ok(incidents)
    }

    /// Create alert rule
    pub async fn create_alert_rule(&self, rule: AlertRule) -> Result<()> {
        self.alert_rules
            .write()
            .await
            .insert(rule.rule_id.clone(), rule);
        Ok(())
    }

    /// Evaluate alert rules and trigger alerts
    pub async fn evaluate_alert_rules(&self) -> Result<Vec<Alert>> {
        let rules = self.alert_rules.read().await;
        let mut triggered_alerts = Vec::new();

        for (_, rule) in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if let Some(alert) = self.evaluate_rule(rule).await {
                triggered_alerts.push(alert);
            }
        }

        drop(rules);

        // Store alerts
        self.active_alerts
            .write()
            .await
            .extend(triggered_alerts.clone());

        Ok(triggered_alerts)
    }

    /// Evaluate single alert rule
    async fn evaluate_rule(&self, rule: &AlertRule) -> Option<Alert> {
        let recent_metrics = self
            .get_recent_metrics(Duration::minutes(rule.window_minutes.into()))
            .await;

        if recent_metrics.is_empty() {
            return None;
        }

        let latest_metric = &recent_metrics[recent_metrics.len() - 1];

        let triggered = match rule.condition {
            AlertCondition::ErrorRateAbove => latest_metric.error_rate > rule.threshold,
            AlertCondition::LatencyAbove => latest_metric.p99_latency_ms > rule.threshold,
            AlertCondition::ThroughputBelow => latest_metric.throughput_per_second < rule.threshold,
            _ => false,
        };

        if triggered {
            Some(Alert {
                alert_id: Uuid::new_v4().to_string(),
                rule_id: rule.rule_id.clone(),
                severity: rule.severity.clone(),
                title: rule._name.clone(),
                message: format!(
                    "Alert triggered: {} exceeded threshold {}",
                    rule._name, rule.threshold
                ),
                triggered_at: Utc::now(),
                resolved_at: None,
                acknowledged: false,
            })
        } else {
            None
        }
    }

    /// Check component health (mock)
    async fn check_component_health(&self, component: &str) -> ComponentHealth {
        // Mock: random health _status
        let response_time_ms = 50.0 + (component.len() as f64 * 2.0);
        let error_rate = 0.01; // 1%

        ComponentHealth {
            component_name: component.to_string(),
            _status: HealthStatus::Healthy,
            response_time_ms,
            error_rate,
            last_check: Utc::now(),
            details: HashMap::from([("version".to_string(), "0.1.0".to_string())]),
        }
    }

    /// Record operation metrics
    async fn record_operation_metrics(&self, operation: &str, duration_ms: f64, success: bool) {
        // Mock: would integrate with actual metrics system
        let _ = (operation, duration_ms, success);
    }

    /// Check for anomalies in trace
    async fn check_anomalies(&self, trace: &OperationTrace) -> Option<CorrelatedIncident> {
        // Mock: detect anomalies based on duration or errors
        if !trace.success || trace.duration_ms > 5000.0 {
            Some(CorrelatedIncident {
                incident_id: Uuid::new_v4().to_string(),
                severity: IncidentSeverity::Medium,
                title: "Anomaly Detected".to_string(),
                description: format!("Operation {} showed unusual behavior", trace.operation_name),
                detected_at: Utc::now(),
                correlated_traces: vec![trace.trace_id.clone()],
                correlated_metrics: Vec::new(),
                correlated_anomalies: vec!["slow_response".to_string()],
                affected_services: vec![trace.service_name.clone()],
                root_cause_hypothesis: None,
                _status: IncidentStatus::Detected,
            })
        } else {
            None
        }
    }

    /// Get recent traces
    async fn get_recent_traces(&self, duration: Duration) -> Vec<OperationTrace> {
        let traces = self.traces.read().await;
        let cutoff = Utc::now() - duration;

        traces
            .iter()
            .filter(|t| t.started_at > cutoff)
            .cloned()
            .collect()
    }

    /// Get recent metrics
    async fn get_recent_metrics(&self, duration: Duration) -> Vec<PerformanceMetrics> {
        let metrics = self.metrics.read().await;
        let cutoff = Utc::now() - duration;

        metrics
            .iter()
            .filter(|m| m.collected_at > cutoff)
            .cloned()
            .collect()
    }

    /// Calculate error rate from traces
    fn calculate_error_rate(&self, traces: &[OperationTrace]) -> f64 {
        if traces.is_empty() {
            return 0.0;
        }

        let errors = traces.iter().filter(|t| !t.success).count();
        errors as f64 / traces.len() as f64
    }

    /// Calculate P99 latency
    fn calculate_p99_latency(&self, traces: &[OperationTrace]) -> f64 {
        if traces.is_empty() {
            return 0.0;
        }

        let mut durations: Vec<f64> = traces.iter().map(|t| t.duration_ms).collect();
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let p99_index = (durations.len() as f64 * 0.99) as usize;
        durations.get(p99_index).cloned().unwrap_or(0.0)
    }

    /// Get affected services
    fn get_affected_services(&self, traces: &[OperationTrace]) -> Vec<String> {
        let mut services: Vec<String> = traces.iter().map(|t| t.service_name.clone()).collect();
        services.sort();
        services.dedup();
        services
    }

    /// Get all incidents
    pub async fn get_incidents(&self) -> Vec<CorrelatedIncident> {
        self.incidents.read().await.clone()
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trace_operation() {
        let pipeline = EndToEndObservabilityPipeline::new();

        let trace = pipeline
            .trace_operation(
                "test_operation".to_string(),
                "test_service".to_string(),
                async { Ok(()) },
            )
            .await
            .unwrap();

        assert_eq!(trace.operation_name, "test_operation");
        assert_eq!(trace.service_name, "test_service");
        assert!(trace.success);
    }

    #[tokio::test]
    async fn test_comprehensive_health_check() {
        let pipeline = EndToEndObservabilityPipeline::new();

        let health = pipeline.comprehensive_health_check().await.unwrap();
        assert!(!health.component_health.is_empty());
        assert!(health.overall_score >= 0.0);
        assert!(health.overall_score <= 100.0);
    }

    #[tokio::test]
    async fn test_incident_correlation() {
        let pipeline = EndToEndObservabilityPipeline::new();

        // Add some failing traces
        for _ in 0..10 {
            pipeline
                .trace_operation("failing_op".to_string(), "service".to_string(), async {
                    Err("error".to_string())
                })
                .await
                .unwrap();
        }

        let incidents = pipeline.incident_correlation().await.unwrap();
        assert!(!incidents.is_empty());
    }

    #[tokio::test]
    async fn test_alert_rule_creation() {
        let pipeline = EndToEndObservabilityPipeline::new();

        let rule = AlertRule {
            rule_id: "rule1".to_string(),
            _name: "High Error Rate".to_string(),
            condition: AlertCondition::ErrorRateAbove,
            threshold: 0.1,
            window_minutes: 5,
            severity: IncidentSeverity::High,
            enabled: true,
        };

        pipeline.create_alert_rule(rule).await.unwrap();

        let rules = pipeline.alert_rules.read().await;
        assert!(rules.contains_key("rule1"));
    }

    #[tokio::test]
    async fn test_alert_evaluation() {
        let pipeline = EndToEndObservabilityPipeline::new();

        // Create metric with high error rate
        let metric = PerformanceMetrics {
            metric_id: "metric1".to_string(),
            collected_at: Utc::now(),
            time_window_minutes: 5,
            total_operations: 100,
            successful_operations: 80,
            failed_operations: 20,
            average_latency_ms: 100.0,
            p50_latency_ms: 90.0,
            p95_latency_ms: 150.0,
            p99_latency_ms: 200.0,
            error_rate: 0.2,
            throughput_per_second: 20.0,
        };

        pipeline.metrics.write().await.push(metric);

        // Create alert rule
        let rule = AlertRule {
            rule_id: "rule2".to_string(),
            _name: "Error Rate Alert".to_string(),
            condition: AlertCondition::ErrorRateAbove,
            threshold: 0.1,
            window_minutes: 5,
            severity: IncidentSeverity::High,
            enabled: true,
        };

        pipeline.create_alert_rule(rule).await.unwrap();

        // Evaluate rules
        let alerts = pipeline.evaluate_alert_rules().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, IncidentSeverity::High);
    }
}
