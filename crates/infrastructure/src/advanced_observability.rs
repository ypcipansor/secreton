//! Advanced Observability Platform
//!
//! Provides comprehensive observability with Prometheus metrics, custom dashboards,
//! alert rules, real-time monitoring streams, and distributed tracing.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ObservabilityError {
    #[error("Metric not found: {0}")]
    MetricNotFound(String),
    #[error("Dashboard not found: {0}")]
    DashboardNotFound(String),
    #[error("Alert rule not found: {0}")]
    AlertRuleNotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

pub type Result<T> = std::result::Result<T, ObservabilityError>;

/// Metric types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub _name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
    pub help: String,
}

/// Histogram bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    pub le: f64,
    pub count: u64,
}

/// Dashboard widget type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WidgetType {
    Graph,
    Table,
    Heatmap,
    SingleStat,
    Gauge,
}

/// Dashboard widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub widget_id: String,
    pub widget_type: WidgetType,
    pub title: String,
    pub metric_query: String,
    pub position: WidgetPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetPosition {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub dashboard_id: String,
    pub _name: String,
    pub description: String,
    pub widgets: Vec<DashboardWidget>,
    pub refresh_interval: u64,
    pub created_at: DateTime<Utc>,
}

/// Alert severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Alert condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    pub metric_name: String,
    pub operator: String,
    pub threshold: f64,
    pub duration: Duration,
}

/// Alert rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: String,
    pub _name: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub notification_channels: Vec<String>,
    pub enabled: bool,
}

/// Alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub rule_id: String,
    pub metric_name: String,
    pub current_value: f64,
    pub threshold: f64,
    pub severity: AlertSeverity,
    pub triggered_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub state: AlertState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertState {
    Firing,
    Resolved,
    Acknowledged,
}

/// Trace span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    pub span_id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub start_time: DateTime<Utc>,
    pub duration_ms: u64,
    pub tags: HashMap<String, String>,
}

/// Advanced Observability Platform
pub struct ObservabilityPlatform {
    metrics: Arc<RwLock<HashMap<String, Metric>>>,
    dashboards: Arc<RwLock<HashMap<String, Dashboard>>>,
    alert_rules: Arc<RwLock<HashMap<String, AlertRule>>>,
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
    traces: Arc<RwLock<HashMap<String, Vec<TraceSpan>>>>,
}

impl ObservabilityPlatform {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            dashboards: Arc::new(RwLock::new(HashMap::new())),
            alert_rules: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(HashMap::new())),
            traces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record metric
    pub async fn record_metric(&self, metric: Metric) -> Result<()> {
        let mut metrics = self.metrics.write().await;

        let _key = format!("{}_{}", metric._name, metric.timestamp.timestamp());
        metrics.insert(_key, metric.clone());

        // Check alert rules
        self.check_alert_rules(&metric).await?;

        Ok(())
    }

    /// Get metric
    pub async fn get_metric(&self, _name: &str) -> Result<Metric> {
        let metrics = self.metrics.read().await;

        // Get latest metric with this _name
        let latest = metrics
            .values()
            .filter(|m| m._name == _name)
            .max_by_key(|m| m.timestamp)
            .cloned();

        latest.ok_or_else(|| ObservabilityError::MetricNotFound(_name.to_string()))
    }

    /// Query metrics
    pub async fn query_metrics(&self, query: &str) -> Vec<Metric> {
        let metrics = self.metrics.read().await;

        // Simple query matching (could be enhanced with PromQL parser)
        metrics
            .values()
            .filter(|m| m._name.contains(query))
            .cloned()
            .collect()
    }

    /// Export Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let metrics = self.metrics.read().await;
        let mut output = String::new();

        let mut grouped: HashMap<String, Vec<&Metric>> = HashMap::new();
        for metric in metrics.values() {
            grouped.entry(metric._name.clone()).or_default().push(metric);
        }

        for (_name, metric_list) in grouped {
            if let Some(first) = metric_list.first() {
                output.push_str(&format!("# HELP {} {}\n", _name, first.help));
                output.push_str(&format!(
                    "# TYPE {} {}\n",
                    _name,
                    match first.metric_type {
                        MetricType::Counter => "counter",
                        MetricType::Gauge => "gauge",
                        MetricType::Histogram => "histogram",
                        MetricType::Summary => "summary",
                    }
                ));

                for metric in metric_list {
                    let labels = if metric.labels.is_empty() {
                        String::new()
                    } else {
                        let label_str: Vec<String> = metric
                            .labels
                            .iter()
                            .map(|(k, v)| format!("{}=\"{}\"", k, v))
                            .collect();
                        format!("{{{}}}", label_str.join(","))
                    };

                    output.push_str(&format!("{}{} {}\n", _name, labels, metric.value));
                }
            }
        }

        output
    }

    /// Create dashboard
    pub async fn create_dashboard(&self, dashboard: Dashboard) -> Result<String> {
        let mut dashboards = self.dashboards.write().await;
        let dashboard_id = dashboard.dashboard_id.clone();
        dashboards.insert(dashboard_id.clone(), dashboard);
        Ok(dashboard_id)
    }

    /// Get dashboard
    pub async fn get_dashboard(&self, dashboard_id: &str) -> Result<Dashboard> {
        let dashboards = self.dashboards.read().await;
        dashboards
            .get(dashboard_id)
            .cloned()
            .ok_or_else(|| ObservabilityError::DashboardNotFound(dashboard_id.to_string()))
    }

    /// Add widget to dashboard
    pub async fn add_widget(&self, dashboard_id: &str, widget: DashboardWidget) -> Result<()> {
        let mut dashboards = self.dashboards.write().await;

        let dashboard = dashboards
            .get_mut(dashboard_id)
            .ok_or_else(|| ObservabilityError::DashboardNotFound(dashboard_id.to_string()))?;

        dashboard.widgets.push(widget);
        Ok(())
    }

    /// Create alert rule
    pub async fn create_alert_rule(&self, rule: AlertRule) -> Result<String> {
        let mut rules = self.alert_rules.write().await;
        let rule_id = rule.rule_id.clone();
        rules.insert(rule_id.clone(), rule);
        Ok(rule_id)
    }

    /// Check alert rules
    async fn check_alert_rules(&self, metric: &Metric) -> Result<()> {
        let rules = self.alert_rules.read().await;
        let mut alerts = self.alerts.write().await;

        for rule in rules.values() {
            if !rule.enabled {
                continue;
            }

            if rule.condition.metric_name == metric._name {
                let should_alert = match rule.condition.operator.as_str() {
                    ">" => metric.value > rule.condition.threshold,
                    ">=" => metric.value >= rule.condition.threshold,
                    "<" => metric.value < rule.condition.threshold,
                    "<=" => metric.value <= rule.condition.threshold,
                    "==" => (metric.value - rule.condition.threshold).abs() < f64::EPSILON,
                    _ => false,
                };

                if should_alert {
                    let alert = Alert {
                        alert_id: Uuid::new_v4().to_string(),
                        rule_id: rule.rule_id.clone(),
                        metric_name: metric._name.clone(),
                        current_value: metric.value,
                        threshold: rule.condition.threshold,
                        severity: rule.severity.clone(),
                        triggered_at: Utc::now(),
                        resolved_at: None,
                        state: AlertState::Firing,
                    };

                    alerts.insert(alert.alert_id.clone(), alert);
                }
            }
        }

        Ok(())
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts
            .values()
            .filter(|a| a.state == AlertState::Firing)
            .cloned()
            .collect()
    }

    /// Acknowledge alert
    pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;

        let alert = alerts
            .get_mut(alert_id)
            .ok_or_else(|| ObservabilityError::AlertRuleNotFound(alert_id.to_string()))?;

        alert.state = AlertState::Acknowledged;
        Ok(())
    }

    /// Resolve alert
    pub async fn resolve_alert(&self, alert_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;

        let alert = alerts
            .get_mut(alert_id)
            .ok_or_else(|| ObservabilityError::AlertRuleNotFound(alert_id.to_string()))?;

        alert.state = AlertState::Resolved;
        alert.resolved_at = Some(Utc::now());
        Ok(())
    }

    /// Record trace span
    pub async fn record_trace_span(&self, span: TraceSpan) -> Result<()> {
        let mut traces = self.traces.write().await;

        traces.entry(span.trace_id.clone()).or_default().push(span);

        Ok(())
    }

    /// Get trace
    pub async fn get_trace(&self, trace_id: &str) -> Vec<TraceSpan> {
        let traces = self.traces.read().await;
        traces.get(trace_id).cloned().unwrap_or_default()
    }

    /// List dashboards
    pub async fn list_dashboards(&self) -> Vec<Dashboard> {
        let dashboards = self.dashboards.read().await;
        dashboards.values().cloned().collect()
    }

    /// List alert rules
    pub async fn list_alert_rules(&self) -> Vec<AlertRule> {
        let rules = self.alert_rules.read().await;
        rules.values().cloned().collect()
    }
}

impl Default for ObservabilityPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_metric() {
        let platform = ObservabilityPlatform::new();

        let metric = Metric {
            _name: "http_requests_total".to_string(),
            metric_type: MetricType::Counter,
            value: 100.0,
            labels: HashMap::new(),
            timestamp: Utc::now(),
            help: "Total HTTP requests".to_string(),
        };

        platform.record_metric(metric.clone()).await.unwrap();

        let retrieved = platform.get_metric(&metric._name).await.unwrap();
        assert_eq!(retrieved._name, "http_requests_total");
        assert_eq!(retrieved.value, 100.0);
    }

    #[tokio::test]
    async fn test_create_dashboard() {
        let platform = ObservabilityPlatform::new();

        let dashboard = Dashboard {
            dashboard_id: "dash1".to_string(),
            _name: "System Overview".to_string(),
            description: "Overview of system metrics".to_string(),
            widgets: vec![],
            refresh_interval: 30,
            created_at: Utc::now(),
        };

        let dashboard_id = platform.create_dashboard(dashboard).await.unwrap();
        assert_eq!(dashboard_id, "dash1");

        let retrieved = platform.get_dashboard(&dashboard_id).await.unwrap();
        assert_eq!(retrieved._name, "System Overview");
    }

    #[tokio::test]
    async fn test_alert_rule_trigger() {
        let platform = ObservabilityPlatform::new();

        let rule = AlertRule {
            rule_id: "rule1".to_string(),
            _name: "High CPU".to_string(),
            condition: AlertCondition {
                metric_name: "cpu_usage".to_string(),
                operator: ">".to_string(),
                threshold: 80.0,
                duration: Duration::minutes(5),
            },
            severity: AlertSeverity::Critical,
            notification_channels: vec!["email".to_string()],
            enabled: true,
        };

        platform.create_alert_rule(rule).await.unwrap();

        let metric = Metric {
            _name: "cpu_usage".to_string(),
            metric_type: MetricType::Gauge,
            value: 85.0,
            labels: HashMap::new(),
            timestamp: Utc::now(),
            help: "CPU usage percentage".to_string(),
        };

        platform.record_metric(metric).await.unwrap();

        let alerts = platform.get_active_alerts().await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let platform = ObservabilityPlatform::new();

        let metric = Metric {
            _name: "http_requests_total".to_string(),
            metric_type: MetricType::Counter,
            value: 100.0,
            labels: HashMap::new(),
            timestamp: Utc::now(),
            help: "Total HTTP requests".to_string(),
        };

        platform.record_metric(metric).await.unwrap();

        let prometheus_output = platform.export_prometheus().await;
        assert!(prometheus_output.contains("# HELP http_requests_total"));
        assert!(prometheus_output.contains("# TYPE http_requests_total counter"));
        assert!(prometheus_output.contains("http_requests_total 100"));
    }

    #[tokio::test]
    async fn test_trace_recording() {
        let platform = ObservabilityPlatform::new();

        let trace_id = Uuid::new_v4().to_string();
        let span = TraceSpan {
            span_id: Uuid::new_v4().to_string(),
            trace_id: trace_id.clone(),
            parent_span_id: None,
            operation_name: "http_request".to_string(),
            start_time: Utc::now(),
            duration_ms: 150,
            tags: HashMap::new(),
        };

        platform.record_trace_span(span).await.unwrap();

        let trace = platform.get_trace(&trace_id).await;
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].operation_name, "http_request");
    }

    #[tokio::test]
    async fn test_acknowledge_alert() {
        let platform = ObservabilityPlatform::new();

        let rule = AlertRule {
            rule_id: "rule1".to_string(),
            _name: "High Memory".to_string(),
            condition: AlertCondition {
                metric_name: "memory_usage".to_string(),
                operator: ">".to_string(),
                threshold: 90.0,
                duration: Duration::minutes(5),
            },
            severity: AlertSeverity::Warning,
            notification_channels: vec![],
            enabled: true,
        };

        platform.create_alert_rule(rule).await.unwrap();

        let metric = Metric {
            _name: "memory_usage".to_string(),
            metric_type: MetricType::Gauge,
            value: 95.0,
            labels: HashMap::new(),
            timestamp: Utc::now(),
            help: "Memory usage percentage".to_string(),
        };

        platform.record_metric(metric).await.unwrap();

        let alerts = platform.get_active_alerts().await;
        assert_eq!(alerts.len(), 1);

        let alert_id = alerts[0].alert_id.clone();
        platform.acknowledge_alert(&alert_id).await.unwrap();

        let alerts = platform.get_active_alerts().await;
        assert_eq!(alerts.len(), 0);
    }
}
