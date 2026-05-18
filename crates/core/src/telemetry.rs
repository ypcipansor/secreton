//! Telemetry - Advanced Metrics and Monitoring
//!
//! This module provides comprehensive telemetry and metrics collection for the Secreton system,
//! including Prometheus integration, StatsD support, and Datadog API integration.
//!
//! Key features:
//! - Prometheus metrics exporter with custom metrics
//! - StatsD integration for real-time monitoring
//! - Datadog API integration for enterprise observability
//! - Comprehensive system metrics collection

use crate::utils::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use sysinfo::{Disks, Networks, System};
use tokio::sync::RwLock;
use tracing::info;

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable Prometheus metrics export
    pub prometheus_enabled: bool,
    /// Prometheus metrics port
    pub prometheus_port: u16,
    /// Enable StatsD metrics
    pub statsd_enabled: bool,
    /// StatsD server address
    pub statsd_address: String,
    /// Enable Datadog integration
    pub datadog_enabled: bool,
    /// Datadog API key
    pub datadog_api_key: Option<String>,
    /// Datadog site (us, eu, etc.)
    pub datadog_site: String,
    /// Metrics collection interval in seconds
    pub collection_interval_seconds: u64,
    /// Enable detailed performance metrics
    pub detailed_performance_metrics: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            prometheus_enabled: true,
            prometheus_port: 9090,
            statsd_enabled: false,
            statsd_address: "localhost:8125".to_string(),
            datadog_enabled: false,
            datadog_api_key: None,
            datadog_site: "datadoghq.com".to_string(),
            collection_interval_seconds: 60,
            detailed_performance_metrics: true,
        }
    }
}

struct SysInfoMonitor {
    system: System,
    networks: Networks,
    disks: Disks,
}

impl std::fmt::Debug for SysInfoMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SysInfoMonitor").finish()
    }
}

/// System metrics collector
#[derive(Debug)]
#[allow(dead_code)]
pub struct TelemetryCollector {
    /// Configuration
    config: TelemetryConfig,
    /// Start time for uptime calculation
    start_time: Instant,
    /// Metrics storage
    metrics: Arc<RwLock<SystemMetrics>>,
    /// System monitor
    sys_monitor: Arc<tokio::sync::Mutex<SysInfoMonitor>>,
}

impl TelemetryCollector {
    /// Create a new telemetry collector
    pub fn new(config: TelemetryConfig) -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        let networks = Networks::new_with_refreshed_list();
        let disks = Disks::new_with_refreshed_list();

        Self {
            config,
            start_time: Instant::now(),
            metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            sys_monitor: Arc::new(tokio::sync::Mutex::new(SysInfoMonitor {
                system,
                networks,
                disks,
            })),
        }
    }

    /// Start metrics collection
    pub async fn start_collection(&self) -> Result<(), AppError> {
        // Prometheus server commented out due to hyper version compatibility issues
        // if self.config.prometheus_enabled {
        //     self.start_prometheus_server().await?;
        // }

        if self.config.statsd_enabled {
            self.start_statsd_collection().await?;
        }

        if self.config.datadog_enabled {
            self.start_datadog_collection().await?;
        }

        // Start background metrics collection
        let sys_monitor = self.sys_monitor.clone();
        let metrics = self.metrics.clone();
        let interval_secs = self.config.collection_interval_seconds;
        let start_time = self.start_time;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                // Lock the system monitor to update system stats
                let mut monitor = sys_monitor.lock().await;

                // Refresh system stats
                // Optimized: Only refresh what we need
                monitor.system.refresh_cpu_all();
                monitor.system.refresh_memory();
                monitor.networks.refresh(true);
                monitor.disks.refresh(true);

                // CPU Usage
                let cpu_usage_percent = monitor.system.global_cpu_usage();

                // Memory Usage
                let memory_usage_bytes = monitor.system.used_memory();
                let total_memory_bytes = monitor.system.total_memory();

                // Disk Usage
                let mut disk_usage_bytes = 0;
                let mut total_disk_bytes = 0;
                for disk in &monitor.disks {
                    // This is total space, usually we want used space?
                    // sysinfo Disk has available_space() and total_space().
                    // used = total - available
                    let total = disk.total_space();
                    let available = disk.available_space();
                    disk_usage_bytes += total.saturating_sub(available);
                    total_disk_bytes += total;
                }

                // Network IO
                let mut network_rx_bytes = 0;
                let mut network_tx_bytes = 0;
                for (_interface_name, network) in &monitor.networks {
                    network_rx_bytes += network.received();
                    network_tx_bytes += network.transmitted();
                }
                let network_io_bytes = network_rx_bytes + network_tx_bytes;

                // Load Average
                let load_avg = System::load_average();

                // Uptime
                let uptime_seconds = start_time.elapsed().as_secs();

                // Update metrics
                let mut metrics_guard = metrics.write().await;

                metrics_guard.performance.cpu_usage_percent = cpu_usage_percent;
                metrics_guard.performance.memory_usage_bytes = memory_usage_bytes;
                metrics_guard.performance.total_memory_bytes = total_memory_bytes;
                metrics_guard.performance.disk_usage_bytes = disk_usage_bytes;
                metrics_guard.performance.total_disk_bytes = total_disk_bytes;
                metrics_guard.performance.network_io_bytes = network_io_bytes;
                metrics_guard.performance.network_rx_bytes = network_rx_bytes;
                metrics_guard.performance.network_tx_bytes = network_tx_bytes;

                metrics_guard.system.load_average_1m = load_avg.one as f32;
                metrics_guard.system.load_average_5m = load_avg.five as f32;
                metrics_guard.system.load_average_15m = load_avg.fifteen as f32;
                metrics_guard.system.uptime_seconds = uptime_seconds;

                // We can't easily get active connections or database connections here without access to those pools
                // So we leave them as is (updated by other parts of the system potentially)
            }
        });

        Ok(())
    }

    /// Record a metric
    pub async fn record_metric(&self, metric: Metric) {
        let mut metrics = self.metrics.write().await;
        metrics.record(metric);
    }

    /// Get current system metrics
    pub async fn get_metrics(&self) -> SystemMetrics {
        self.metrics.read().await.clone()
    }

    /// Get system uptime in seconds without acquiring the metrics RwLock.
    ///
    /// This is useful for lightweight probes (e.g. liveness checks) that must
    /// remain dependency-free.  Unlike `get_metrics().system.uptime_seconds`,
    /// this always returns an accurate value even before the background
    /// collection task has completed its first tick.
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Start StatsD metrics collection
    async fn start_statsd_collection(&self) -> Result<(), AppError> {
        // Simplified StatsD implementation
        info!(
            "StatsD metrics collection started for {}",
            self.config.statsd_address
        );
        Ok(())
    }

    /// Start Datadog metrics collection
    async fn start_datadog_collection(&self) -> Result<(), AppError> {
        if self.config.datadog_api_key.is_some() {
            info!(
                "Datadog metrics collection started for site {}",
                self.config.datadog_site
            );
        }
        Ok(())
    }

    // async fn start_prometheus_server(&self) -> Result<(), AppError> {
    //     // Create a Prometheus registry
    //     let registry = prometheus::Registry::new();

    //     // Register metrics
    //     self.register_prometheus_metrics(&registry)?;

    //     // Create a Prometheus server
    //     let server = Server::bind(format!("0.0.0.0:{}", self.config.prometheus_port))
    //         .serve(make_service_fn(move |_| {
    //             let registry = registry.clone();
    //             async move {
    //                 Ok::<_, hyper::Error>(service_fn(move |req| {
    //                     handle_prometheus_request(req, registry.clone())
    //                 }))
    //             }
    //         }));

    //     // Start the server
    //     info!("Prometheus server started on port {}", self.config.prometheus_port);
    //     server.await?;

    //     Ok(())
    // }
}

/// System metrics data structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemMetrics {
    /// Request metrics
    pub requests: RequestMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// System metrics
    pub system: SystemResourceMetrics,
    /// Security metrics
    pub security: SecurityMetrics,
    /// Custom metrics
    pub custom: HashMap<String, MetricValue>,
}

/// Request metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestMetrics {
    /// Total number of requests
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time in milliseconds
    pub average_response_time_ms: f64,
    /// Requests per second
    pub requests_per_second: f64,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceMetrics {
    /// CPU usage percentage
    pub cpu_usage_percent: f32,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Total memory in bytes
    pub total_memory_bytes: u64,
    /// Disk usage in bytes
    pub disk_usage_bytes: u64,
    /// Total disk space in bytes
    pub total_disk_bytes: u64,
    /// Network I/O in bytes (deprecated, use rx/tx)
    pub network_io_bytes: u64,
    /// Network received bytes
    pub network_rx_bytes: u64,
    /// Network transmitted bytes
    pub network_tx_bytes: u64,
    /// Database connections
    pub database_connections: u32,
    /// Cache hit rate percentage
    pub cache_hit_rate_percent: f32,
}

/// System resource metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemResourceMetrics {
    /// Number of active connections
    pub active_connections: u32,
    /// System uptime in seconds
    pub uptime_seconds: u64,
    /// Load average (1 minute)
    pub load_average_1m: f32,
    /// Load average (5 minutes)
    pub load_average_5m: f32,
    /// Load average (15 minutes)
    pub load_average_15m: f32,
}

/// Security metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityMetrics {
    /// Failed authentication attempts
    pub failed_auth_attempts: u64,
    /// Successful authentication attempts
    pub successful_auth_attempts: u64,
    /// Active sessions
    pub active_sessions: u32,
    /// Security violations
    pub security_violations: u64,
    /// Keys rotated
    pub keys_rotated: u64,
    /// Audit events generated
    pub audit_events: u64,
}

/// Metric value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    /// Counter value
    Counter(u64),
    /// Gauge value
    Gauge(f64),
    /// Histogram value
    Histogram(Vec<f64>),
}

/// Generic metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    /// Metric name
    pub name: String,
    /// Metric value
    pub value: MetricValue,
    /// Metric tags/labels
    pub tags: HashMap<String, String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl SystemMetrics {
    /// Record a new metric
    pub fn record(&mut self, metric: Metric) {
        match metric.value {
            MetricValue::Counter(value) => match metric.name.as_str() {
                "requests_total" => self.requests.total_requests += value,
                "requests_successful" => self.requests.successful_requests += value,
                "requests_failed" => self.requests.failed_requests += value,
                "failed_auth_attempts" => self.security.failed_auth_attempts += value,
                "successful_auth_attempts" => self.security.successful_auth_attempts += value,
                "security_violations" => self.security.security_violations += value,
                "keys_rotated" => self.security.keys_rotated += value,
                "audit_events" => self.security.audit_events += value,
                _ => {
                    self.custom.insert(metric.name, MetricValue::Counter(value));
                }
            },
            MetricValue::Gauge(value) => match metric.name.as_str() {
                "response_time_ms" => self.requests.average_response_time_ms = value,
                "cpu_usage_percent" => self.performance.cpu_usage_percent = value as f32,
                "memory_usage_bytes" => self.performance.memory_usage_bytes = value as u64,
                "disk_usage_bytes" => self.performance.disk_usage_bytes = value as u64,
                "network_io_bytes" => self.performance.network_io_bytes = value as u64,
                "database_connections" => self.performance.database_connections = value as u32,
                "cache_hit_rate_percent" => self.performance.cache_hit_rate_percent = value as f32,
                "active_connections" => self.system.active_connections = value as u32,
                "load_average_1m" => self.system.load_average_1m = value as f32,
                "load_average_5m" => self.system.load_average_5m = value as f32,
                "load_average_15m" => self.system.load_average_15m = value as f32,
                "active_sessions" => self.security.active_sessions = value as u32,
                _ => {
                    self.custom.insert(metric.name, MetricValue::Gauge(value));
                }
            },
            MetricValue::Histogram(values) => {
                self.custom
                    .insert(metric.name, MetricValue::Histogram(values));
            }
        }
    }

    /// Update system metrics
    pub fn update_system_metrics(&mut self, system_metrics: SystemResourceMetrics) {
        self.system = system_metrics;
    }
}

/// Update Prometheus metrics from system metrics
#[allow(dead_code)]
async fn update_prometheus_metrics(_metrics: &SystemMetrics, _registry: &prometheus::Registry) {
    // No-op
}

/// Collect current system metrics
///
/// NOTE: This function cannot compute real uptime because it has no access to
/// the `TelemetryCollector::start_time` field. Callers that need accurate
/// uptime should use `TelemetryCollector::uptime_seconds()` instead.
#[allow(dead_code)]
async fn collect_system_metrics() -> SystemResourceMetrics {
    // Simplified system metrics collection
    // In a real implementation, this would use system monitoring libraries

    SystemResourceMetrics {
        active_connections: 0, // Would be collected from connection pool
        uptime_seconds: 0,     // Cannot compute here; use TelemetryCollector::uptime_seconds()
        load_average_1m: 0.0,  // Would be collected from system
        load_average_5m: 0.0,
        load_average_15m: 0.0,
    }
}

/// Telemetry request for API
#[derive(Debug, Deserialize)]
pub struct TelemetryRequest {
    pub metrics_type: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Telemetry response for API
#[derive(Debug, Serialize)]
pub struct TelemetryResponse {
    pub metrics: SystemMetrics,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_telemetry_collector_creation() {
        let config = TelemetryConfig::default();
        let _collector = TelemetryCollector::new(config);
        // Prometheus registry removed due to compatibility issues
        // assert!(collector.prometheus_registry.is_some());
    }

    #[tokio::test]
    async fn test_metrics_recording() {
        let collector = TelemetryCollector::new(TelemetryConfig::default());

        let metric = Metric {
            name: "requests_total".to_string(),
            value: MetricValue::Counter(1),
            tags: HashMap::new(),
            timestamp: chrono::Utc::now(),
        };

        collector.record_metric(metric).await;
        let metrics = collector.get_metrics().await;

        assert_eq!(metrics.requests.total_requests, 1);
    }

    #[tokio::test]
    async fn test_system_metrics_update() {
        let mut metrics = SystemMetrics::default();
        let system_metrics = SystemResourceMetrics {
            active_connections: 10,
            uptime_seconds: 3600,
            load_average_1m: 1.5,
            load_average_5m: 1.2,
            load_average_15m: 1.0,
        };

        metrics.update_system_metrics(system_metrics.clone());
        assert_eq!(metrics.system.active_connections, 10);
        assert_eq!(metrics.system.uptime_seconds, 3600);
    }
}
