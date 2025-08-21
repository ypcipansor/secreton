//! Metrics collection module for the Brankas agent

use crate::config::MetricsConfig;
use brankas_core::{CoreResult, CoreError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::mpsc;

/// Metric types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    /// Metric name
    pub name: String,
    
    /// Metric type
    pub metric_type: MetricType,
    
    /// Metric value
    pub value: f64,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Labels/tags
    pub labels: HashMap<String, String>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl MetricPoint {
    /// Create a new metric point
    pub fn new(name: String, metric_type: MetricType, value: f64) -> Self {
        Self {
            name,
            metric_type,
            value,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            labels: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add a label
    pub fn with_label(mut self, key: String, value: String) -> Self {
        self.labels.insert(key, value);
        self
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Metric series (time series data for a metric)
#[derive(Debug, Clone)]
pub struct MetricSeries {
    /// Metric name
    pub name: String,
    
    /// Metric type
    pub metric_type: MetricType,
    
    /// Data points
    pub points: VecDeque<MetricPoint>,
    
    /// Maximum number of points to retain
    pub max_points: usize,
}

impl MetricSeries {
    /// Create a new metric series
    pub fn new(name: String, metric_type: MetricType, max_points: usize) -> Self {
        Self {
            name,
            metric_type,
            points: VecDeque::new(),
            max_points,
        }
    }
    
    /// Add a data point
    pub fn add_point(&mut self, point: MetricPoint) {
        self.points.push_back(point);
        
        // Maintain max points limit
        while self.points.len() > self.max_points {
            self.points.pop_front();
        }
    }
    
    /// Get latest value
    pub fn latest_value(&self) -> Option<f64> {
        self.points.back().map(|p| p.value)
    }
    
    /// Get average value over time period
    pub fn average_value(&self, duration: Duration) -> Option<f64> {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - duration.as_secs();
        
        let recent_points: Vec<&MetricPoint> = self.points
            .iter()
            .filter(|p| p.timestamp >= cutoff_time)
            .collect();
        
        if recent_points.is_empty() {
            None
        } else {
            let sum: f64 = recent_points.iter().map(|p| p.value).sum();
            Some(sum / recent_points.len() as f64)
        }
    }
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    
    /// Disk usage percentage
    pub disk_usage_percent: f64,
    
    /// Network bytes sent per second
    pub network_bytes_sent_per_sec: f64,
    
    /// Network bytes received per second
    pub network_bytes_received_per_sec: f64,
    
    /// Load average (1 minute)
    pub load_average_1m: f64,
    
    /// Number of active connections
    pub active_connections: u32,
    
    /// Number of active processes
    pub active_processes: u32,
    
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Number of security events in last hour
    pub security_events_per_hour: u32,
    
    /// Number of blocked IPs
    pub blocked_ips_count: u32,
    
    /// Number of quarantined files
    pub quarantined_files_count: u32,
    
    /// Number of failed authentication attempts
    pub failed_auth_attempts: u32,
    
    /// Number of intrusion attempts detected
    pub intrusion_attempts: u32,
    
    /// Number of malware files detected
    pub malware_detections: u32,
    
    /// Number of vulnerability findings
    pub vulnerability_findings: u32,
    
    /// Number of compliance violations
    pub compliance_violations: u32,
}

/// Alert metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertMetrics {
    /// Total number of active alerts
    pub active_alerts_count: u32,
    
    /// Number of critical alerts
    pub critical_alerts_count: u32,
    
    /// Number of warning alerts
    pub warning_alerts_count: u32,
    
    /// Number of info alerts
    pub info_alerts_count: u32,
    
    /// Average alert response time in minutes
    pub avg_alert_response_time_minutes: f64,
    
    /// Alert resolution rate (percentage)
    pub alert_resolution_rate_percent: f64,
    
    /// Number of alerts sent via email
    pub email_alerts_sent: u32,
    
    /// Number of alerts sent via webhook
    pub webhook_alerts_sent: u32,
    
    /// Number of alerts sent via Slack
    pub slack_alerts_sent: u32,
}

/// Health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Overall health status (0=Unknown, 1=Healthy, 2=Degraded, 3=Unhealthy)
    pub overall_health_status: u8,
    
    /// Number of healthy services
    pub healthy_services_count: u32,
    
    /// Number of degraded services
    pub degraded_services_count: u32,
    
    /// Number of unhealthy services
    pub unhealthy_services_count: u32,
    
    /// Average health check response time in milliseconds
    pub avg_health_check_response_time_ms: f64,
    
    /// Database health status
    pub database_health_status: u8,
    
    /// API health status
    pub api_health_status: u8,
    
    /// External services health status
    pub external_services_health_status: u8,
}

/// Comprehensive metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// Timestamp
    pub timestamp: u64,
    
    /// Performance metrics
    pub performance: PerformanceMetrics,
    
    /// Security metrics
    pub security: SecurityMetrics,
    
    /// Alert metrics
    pub alerts: AlertMetrics,
    
    /// Health metrics
    pub health: HealthMetrics,
    
    /// Custom metrics
    pub custom: HashMap<String, f64>,
}

/// Metrics collector
#[derive(Debug)]
pub struct MetricsCollector {
    /// Configuration
    config: MetricsConfig,
    
    /// Metric series storage
    metrics: Arc<RwLock<HashMap<String, MetricSeries>>>,
    
    /// Metric points receiver
    metric_receiver: mpsc::UnboundedReceiver<MetricPoint>,
    
    /// HTTP client for external metrics systems
    http_client: reqwest::Client,
    
    /// Agent start time
    start_time: SystemTime,
    
    /// Running flag
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(
        config: MetricsConfig,
        metric_receiver: mpsc::UnboundedReceiver<MetricPoint>,
    ) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
            metric_receiver,
            http_client: reqwest::Client::new(),
            start_time: SystemTime::now(),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    
    /// Start metrics collection
    pub async fn start(&mut self) -> CoreResult<()> {
        tracing::info!("Starting metrics collector");
        
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);
        
        let collection_interval = Duration::from_secs(self.config.collection_interval_seconds);
        let mut last_collection = SystemTime::now();
        
        while self.running.load(std::sync::atomic::Ordering::SeqCst) {
            // Process incoming metric points
            self.process_metric_points().await?;
            
            // Collect system metrics periodically
            if last_collection.elapsed().unwrap_or(Duration::ZERO) >= collection_interval {
                self.collect_system_metrics().await?;
                last_collection = SystemTime::now();
            }
            
            // Export metrics if configured
            if self.config.prometheus_enabled {
                self.export_prometheus_metrics().await?;
            }
            
            if self.config.statsd_enabled {
                self.export_statsd_metrics().await?;
            }
            
            // Clean up old metrics
            self.cleanup_old_metrics().await?;
            
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        Ok(())
    }
    
    /// Stop metrics collection
    pub async fn stop(&mut self) -> CoreResult<()> {
        tracing::info!("Stopping metrics collector");
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    
    /// Process incoming metric points
    async fn process_metric_points(&mut self) -> CoreResult<()> {
        while let Ok(point) = self.metric_receiver.try_recv() {
            self.add_metric_point(point).await?;
        }
        Ok(())
    }
    
    /// Add a metric point
    pub async fn add_metric_point(&self, point: MetricPoint) -> CoreResult<()> {
        let series_key = format!("{}:{:?}", point.name, point.metric_type);
        
        let mut metrics = self.metrics.write().unwrap();
        let series = metrics
            .entry(series_key.clone())
            .or_insert_with(|| MetricSeries::new(point.name.clone(), point.metric_type.clone(), 1000));
        
        series.add_point(point);
        
        Ok(())
    }
    
    /// Collect system metrics
    async fn collect_system_metrics(&self) -> CoreResult<()> {
        tracing::debug!("Collecting system metrics");
        
        // Performance metrics
        let cpu_usage = self.get_cpu_usage().await?;
        let memory_usage = self.get_memory_usage().await?;
        let disk_usage = self.get_disk_usage().await?;
        let load_average = self.get_load_average().await?;
        let network_stats = self.get_network_stats().await?;
        
        // Create metric points
        let points = vec![
            MetricPoint::new("system_cpu_usage_percent".to_string(), MetricType::Gauge, cpu_usage),
            MetricPoint::new("system_memory_usage_percent".to_string(), MetricType::Gauge, memory_usage),
            MetricPoint::new("system_disk_usage_percent".to_string(), MetricType::Gauge, disk_usage),
            MetricPoint::new("system_load_average_1m".to_string(), MetricType::Gauge, load_average),
            MetricPoint::new("system_network_bytes_sent".to_string(), MetricType::Counter, network_stats.0),
            MetricPoint::new("system_network_bytes_received".to_string(), MetricType::Counter, network_stats.1),
        ];
        
        // Add to metrics storage
        for point in points {
            self.add_metric_point(point).await?;
        }
        
        Ok(())
    }
    
    /// Get CPU usage percentage
    async fn get_cpu_usage(&self) -> CoreResult<f64> {
        // This is a simplified mock implementation
        Ok(rand::random::<f64>() * 100.0)
    }
    
    /// Get memory usage percentage
    async fn get_memory_usage(&self) -> CoreResult<f64> {
        // This is a simplified mock implementation
        Ok(rand::random::<f64>() * 80.0 + 10.0)
    }
    
    /// Get disk usage percentage
    async fn get_disk_usage(&self) -> CoreResult<f64> {
        // This is a simplified mock implementation
        Ok(rand::random::<f64>() * 70.0 + 20.0)
    }
    
    /// Get load average
    async fn get_load_average(&self) -> CoreResult<f64> {
        // This is a simplified mock implementation
        Ok(rand::random::<f64>() * 4.0)
    }
    
    /// Get network statistics (bytes sent, bytes received)
    async fn get_network_stats(&self) -> CoreResult<(f64, f64)> {
        // This is a simplified mock implementation
        Ok((rand::random::<f64>() * 1000000.0, rand::random::<f64>() * 1000000.0))
    }
    
    /// Export metrics to Prometheus format
    async fn export_prometheus_metrics(&self) -> CoreResult<()> {
        if !self.config.prometheus_enabled {
            return Ok(());
        }
        
        tracing::debug!("Exporting Prometheus metrics");
        
        let metrics = self.metrics.read().unwrap();
        let mut prometheus_output = String::new();
        
        for (_, series) in metrics.iter() {
            if let Some(latest) = series.points.back() {
                prometheus_output.push_str(&format!(
                    "# TYPE {} {}\n",
                    series.name.replace('-', "_"),
                    match series.metric_type {
                        MetricType::Counter => "counter",
                        MetricType::Gauge => "gauge",
                        MetricType::Histogram => "histogram",
                        MetricType::Summary => "summary",
                    }
                ));
                
                let mut labels = String::new();
                if !latest.labels.is_empty() {
                    let label_pairs: Vec<String> = latest.labels
                        .iter()
                        .map(|(k, v)| format!("{}=\"{}\"", k, v))
                        .collect();
                    labels = format!("{{{}}}", label_pairs.join(","));
                }
                
                prometheus_output.push_str(&format!(
                    "{}{} {}\n",
                    series.name.replace('-', "_"),
                    labels,
                    latest.value
                ));
            }
        }
        
        // In a real implementation, this would be served via HTTP endpoint
        tracing::debug!("Prometheus metrics: {} lines", prometheus_output.lines().count());
        
        Ok(())
    }
    
    /// Export metrics to StatsD
    async fn export_statsd_metrics(&self) -> CoreResult<()> {
        if !self.config.statsd_enabled {
            return Ok(());
        }
        
        tracing::debug!("Exporting StatsD metrics");
        
        let metrics = self.metrics.read().unwrap();
        
        for (_, series) in metrics.iter() {
            if let Some(latest) = series.points.back() {
                let metric_type_suffix = match series.metric_type {
                    MetricType::Counter => "c",
                    MetricType::Gauge => "g",
                    MetricType::Histogram => "h",
                    MetricType::Summary => "ms",
                };
                
                let statsd_metric = format!("{}:{}|{}", series.name, latest.value, metric_type_suffix);
                
                // In a real implementation, this would be sent via UDP to StatsD server
                tracing::debug!("StatsD metric: {}", statsd_metric);
            }
        }
        
        Ok(())
    }
    
    /// Clean up old metrics
    async fn cleanup_old_metrics(&self) -> CoreResult<()> {
        let retention_cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.config.retention_seconds;
        
        let mut metrics = self.metrics.write().unwrap();
        
        for (_, series) in metrics.iter_mut() {
            series.points.retain(|point| point.timestamp >= retention_cutoff);
        }
        
        // Remove empty series
        metrics.retain(|_, series| !series.points.is_empty());
        
        Ok(())
    }
    
    /// Get current metrics summary
    pub async fn get_metrics_summary(&self) -> MetricsSummary {
        let metrics = self.metrics.read().unwrap();
        
        // Extract performance metrics
        let performance = PerformanceMetrics {
            cpu_usage_percent: self.get_metric_value(&metrics, "system_cpu_usage_percent").unwrap_or(0.0),
            memory_usage_percent: self.get_metric_value(&metrics, "system_memory_usage_percent").unwrap_or(0.0),
            disk_usage_percent: self.get_metric_value(&metrics, "system_disk_usage_percent").unwrap_or(0.0),
            network_bytes_sent_per_sec: self.get_metric_value(&metrics, "system_network_bytes_sent").unwrap_or(0.0),
            network_bytes_received_per_sec: self.get_metric_value(&metrics, "system_network_bytes_received").unwrap_or(0.0),
            load_average_1m: self.get_metric_value(&metrics, "system_load_average_1m").unwrap_or(0.0),
            active_connections: self.get_metric_value(&metrics, "system_active_connections").unwrap_or(0.0) as u32,
            active_processes: self.get_metric_value(&metrics, "system_active_processes").unwrap_or(0.0) as u32,
            uptime_seconds: self.start_time.elapsed().unwrap_or(Duration::ZERO).as_secs(),
        };
        
        // Extract security metrics
        let security = SecurityMetrics {
            security_events_per_hour: self.get_metric_value(&metrics, "security_events_per_hour").unwrap_or(0.0) as u32,
            blocked_ips_count: self.get_metric_value(&metrics, "security_blocked_ips").unwrap_or(0.0) as u32,
            quarantined_files_count: self.get_metric_value(&metrics, "security_quarantined_files").unwrap_or(0.0) as u32,
            failed_auth_attempts: self.get_metric_value(&metrics, "security_failed_auth").unwrap_or(0.0) as u32,
            intrusion_attempts: self.get_metric_value(&metrics, "security_intrusion_attempts").unwrap_or(0.0) as u32,
            malware_detections: self.get_metric_value(&metrics, "security_malware_detections").unwrap_or(0.0) as u32,
            vulnerability_findings: self.get_metric_value(&metrics, "security_vulnerability_findings").unwrap_or(0.0) as u32,
            compliance_violations: self.get_metric_value(&metrics, "security_compliance_violations").unwrap_or(0.0) as u32,
        };
        
        // Extract alert metrics
        let alerts = AlertMetrics {
            active_alerts_count: self.get_metric_value(&metrics, "alerts_active").unwrap_or(0.0) as u32,
            critical_alerts_count: self.get_metric_value(&metrics, "alerts_critical").unwrap_or(0.0) as u32,
            warning_alerts_count: self.get_metric_value(&metrics, "alerts_warning").unwrap_or(0.0) as u32,
            info_alerts_count: self.get_metric_value(&metrics, "alerts_info").unwrap_or(0.0) as u32,
            avg_alert_response_time_minutes: self.get_metric_value(&metrics, "alerts_avg_response_time").unwrap_or(0.0),
            alert_resolution_rate_percent: self.get_metric_value(&metrics, "alerts_resolution_rate").unwrap_or(0.0),
            email_alerts_sent: self.get_metric_value(&metrics, "alerts_email_sent").unwrap_or(0.0) as u32,
            webhook_alerts_sent: self.get_metric_value(&metrics, "alerts_webhook_sent").unwrap_or(0.0) as u32,
            slack_alerts_sent: self.get_metric_value(&metrics, "alerts_slack_sent").unwrap_or(0.0) as u32,
        };
        
        // Extract health metrics
        let health = HealthMetrics {
            overall_health_status: self.get_metric_value(&metrics, "health_overall_status").unwrap_or(0.0) as u8,
            healthy_services_count: self.get_metric_value(&metrics, "health_healthy_services").unwrap_or(0.0) as u32,
            degraded_services_count: self.get_metric_value(&metrics, "health_degraded_services").unwrap_or(0.0) as u32,
            unhealthy_services_count: self.get_metric_value(&metrics, "health_unhealthy_services").unwrap_or(0.0) as u32,
            avg_health_check_response_time_ms: self.get_metric_value(&metrics, "health_avg_response_time").unwrap_or(0.0),
            database_health_status: self.get_metric_value(&metrics, "health_database_status").unwrap_or(0.0) as u8,
            api_health_status: self.get_metric_value(&metrics, "health_api_status").unwrap_or(0.0) as u8,
            external_services_health_status: self.get_metric_value(&metrics, "health_external_services_status").unwrap_or(0.0) as u8,
        };
        
        // Extract custom metrics
        let mut custom = HashMap::new();
        for (key, series) in metrics.iter() {
            if key.starts_with("custom_") {
                if let Some(value) = series.latest_value() {
                    custom.insert(series.name.clone(), value);
                }
            }
        }
        
        MetricsSummary {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            performance,
            security,
            alerts,
            health,
            custom,
        }
    }
    
    /// Get metric value by name
    fn get_metric_value(&self, metrics: &HashMap<String, MetricSeries>, name: &str) -> Option<f64> {
        // Try to find the metric with any type
        for (_, series) in metrics.iter() {
            if series.name == name {
                return series.latest_value();
            }
        }
        None
    }
    
    /// Get metric series by name
    pub fn get_metric_series(&self, name: &str) -> Option<MetricSeries> {
        let metrics = self.metrics.read().unwrap();
        for (_, series) in metrics.iter() {
            if series.name == name {
                return Some(series.clone());
            }
        }
        None
    }
    
    /// Record a custom metric
    pub async fn record_metric(&self, name: String, metric_type: MetricType, value: f64, labels: HashMap<String, String>) -> CoreResult<()> {
        let point = MetricPoint::new(name, metric_type, value);
        let point_with_labels = labels.into_iter().fold(point, |acc, (k, v)| acc.with_label(k, v));
        
        self.add_metric_point(point_with_labels).await
    }
    
    /// Get all metric names
    pub fn get_metric_names(&self) -> Vec<String> {
        let metrics = self.metrics.read().unwrap();
        metrics.values().map(|series| series.name.clone()).collect()
    }
    
    /// Check if metrics collector is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Get uptime in seconds
    pub fn get_uptime(&self) -> u64 {
        self.start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}
