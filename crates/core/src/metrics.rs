//! Metrics and monitoring for Secreton

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// System metrics collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,

    /// Memory usage in bytes
    pub memory_used: u64,

    /// Memory total in bytes
    pub memory_total: u64,

    /// Disk usage in bytes
    pub disk_used: u64,

    /// Disk total in bytes
    pub disk_total: u64,

    /// Active connections count
    pub active_connections: u32,

    /// Request rate per second
    pub request_rate: f64,

    /// Average response time in milliseconds
    pub avg_response_time: f64,

    /// Error rate percentage
    pub error_rate: f64,

    /// Timestamp when metrics were collected
    pub timestamp: DateTime<Utc>,
}

/// Security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Failed login attempts in the last hour
    pub failed_logins: u32,

    /// Successful logins in the last hour
    pub successful_logins: u32,

    /// Active sessions count
    pub active_sessions: u32,

    /// MFA usage rate percentage
    pub mfa_usage_rate: f64,

    /// Password policy violations
    pub password_violations: u32,

    /// Suspicious activities detected
    pub suspicious_activities: u32,

    /// Access denials in the last hour
    pub access_denials: u32,

    /// Timestamp when metrics were collected
    pub timestamp: DateTime<Utc>,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Database query average time in milliseconds
    pub db_avg_query_time: f64,

    /// Database connection pool usage
    pub db_pool_usage: f64,

    /// Cache hit rate percentage
    pub cache_hit_rate: f64,

    /// Encryption operations per second
    pub encryption_ops_per_sec: f64,

    /// Decryption operations per second
    pub decryption_ops_per_sec: f64,

    /// Average encryption time in milliseconds
    pub avg_encryption_time: f64,

    /// Average decryption time in milliseconds
    pub avg_decryption_time: f64,

    /// Timestamp when metrics were collected
    pub timestamp: DateTime<Utc>,
}

/// Combined metrics structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretonMetrics {
    pub system: SystemMetrics,
    pub security: SecurityMetrics,
    pub performance: PerformanceMetrics,
    pub custom: HashMap<String, serde_json::Value>,
}

/// Performance timer for measuring operation durations
#[derive(Debug)]
pub struct PerformanceTimer {
    start_time: Instant,
    operation_name: String,
}

impl PerformanceTimer {
    /// Start a new performance timer
    pub fn start(operation_name: String) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name,
        }
    }

    /// Stop the timer and return duration in milliseconds
    pub fn stop(self) -> f64 {
        let duration = self.start_time.elapsed();
        duration.as_secs_f64() * 1000.0
    }

    /// Stop the timer and get measurement
    pub fn measure(self) -> PerformanceMeasurement {
        let duration = self.start_time.elapsed();
        let duration_ms = duration.as_secs_f64() * 1000.0;
        PerformanceMeasurement {
            operation: self.operation_name,
            duration_ms,
            timestamp: Utc::now(),
        }
    }
}

/// Performance measurement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMeasurement {
    pub operation: String,
    pub duration_ms: f64,
    pub timestamp: DateTime<Utc>,
}

/// Metrics collector trait
pub trait MetricsCollector: Send + Sync {
    /// Record a counter metric
    fn increment_counter(&self, name: &str, value: u64, tags: Option<&HashMap<String, String>>);

    /// Record a gauge metric
    fn set_gauge(&self, name: &str, value: f64, tags: Option<&HashMap<String, String>>);

    /// Record a histogram metric
    fn record_histogram(&self, name: &str, value: f64, tags: Option<&HashMap<String, String>>);

    /// Record a timer metric
    fn record_timer(&self, name: &str, duration_ms: f64, tags: Option<&HashMap<String, String>>);

    /// Get current system metrics
    fn get_system_metrics(&self) -> SystemMetrics;

    /// Get current security metrics  
    fn get_security_metrics(&self) -> SecurityMetrics;

    /// Get current performance metrics
    fn get_performance_metrics(&self) -> PerformanceMetrics;
}

/// In-memory metrics collector for testing and development
pub struct InMemoryMetricsCollector {
    counters: std::sync::RwLock<HashMap<String, u64>>,
    gauges: std::sync::RwLock<HashMap<String, f64>>,
    histograms: std::sync::RwLock<HashMap<String, Vec<f64>>>,
}

impl InMemoryMetricsCollector {
    pub fn new() -> Self {
        Self {
            counters: std::sync::RwLock::new(HashMap::new()),
            gauges: std::sync::RwLock::new(HashMap::new()),
            histograms: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn get_counter(&self, name: &str) -> Option<u64> {
        self.counters.read().unwrap().get(name).copied()
    }

    pub fn get_gauge(&self, name: &str) -> Option<f64> {
        self.gauges.read().unwrap().get(name).copied()
    }
}

impl Default for InMemoryMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector for InMemoryMetricsCollector {
    fn increment_counter(&self, name: &str, value: u64, _tags: Option<&HashMap<String, String>>) {
        let mut counters = self.counters.write().unwrap();
        *counters.entry(name.to_string()).or_insert(0) += value;
    }

    fn set_gauge(&self, name: &str, value: f64, _tags: Option<&HashMap<String, String>>) {
        let mut gauges = self.gauges.write().unwrap();
        gauges.insert(name.to_string(), value);
    }

    fn record_histogram(&self, name: &str, value: f64, _tags: Option<&HashMap<String, String>>) {
        let mut histograms = self.histograms.write().unwrap();
        histograms
            .entry(name.to_string())
            .or_default()
            .push(value);
    }

    fn record_timer(&self, name: &str, duration_ms: f64, tags: Option<&HashMap<String, String>>) {
        self.record_histogram(name, duration_ms, tags);
    }

    fn get_system_metrics(&self) -> SystemMetrics {
        SystemMetrics {
            cpu_usage: self.get_gauge("system.cpu_usage").unwrap_or(0.0),
            memory_used: self.get_counter("system.memory_used").unwrap_or(0),
            memory_total: self.get_counter("system.memory_total").unwrap_or(0),
            disk_used: self.get_counter("system.disk_used").unwrap_or(0),
            disk_total: self.get_counter("system.disk_total").unwrap_or(0),
            active_connections: self.get_counter("system.active_connections").unwrap_or(0) as u32,
            request_rate: self.get_gauge("system.request_rate").unwrap_or(0.0),
            avg_response_time: self.get_gauge("system.avg_response_time").unwrap_or(0.0),
            error_rate: self.get_gauge("system.error_rate").unwrap_or(0.0),
            timestamp: Utc::now(),
        }
    }

    fn get_security_metrics(&self) -> SecurityMetrics {
        SecurityMetrics {
            failed_logins: self.get_counter("security.failed_logins").unwrap_or(0) as u32,
            successful_logins: self.get_counter("security.successful_logins").unwrap_or(0) as u32,
            active_sessions: self.get_counter("security.active_sessions").unwrap_or(0) as u32,
            mfa_usage_rate: self.get_gauge("security.mfa_usage_rate").unwrap_or(0.0),
            password_violations: self
                .get_counter("security.password_violations")
                .unwrap_or(0) as u32,
            suspicious_activities: self
                .get_counter("security.suspicious_activities")
                .unwrap_or(0) as u32,
            access_denials: self.get_counter("security.access_denials").unwrap_or(0) as u32,
            timestamp: Utc::now(),
        }
    }

    fn get_performance_metrics(&self) -> PerformanceMetrics {
        PerformanceMetrics {
            db_avg_query_time: self
                .get_gauge("performance.db_avg_query_time")
                .unwrap_or(0.0),
            db_pool_usage: self.get_gauge("performance.db_pool_usage").unwrap_or(0.0),
            cache_hit_rate: self.get_gauge("performance.cache_hit_rate").unwrap_or(0.0),
            encryption_ops_per_sec: self
                .get_gauge("performance.encryption_ops_per_sec")
                .unwrap_or(0.0),
            decryption_ops_per_sec: self
                .get_gauge("performance.decryption_ops_per_sec")
                .unwrap_or(0.0),
            avg_encryption_time: self
                .get_gauge("performance.avg_encryption_time")
                .unwrap_or(0.0),
            avg_decryption_time: self
                .get_gauge("performance.avg_decryption_time")
                .unwrap_or(0.0),
            timestamp: Utc::now(),
        }
    }
}

/// Health check status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub response_time_ms: f64,
}

/// Health monitor for system components
pub struct HealthMonitor {
    checks: Vec<Box<dyn HealthCheckProvider>>,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    pub fn add_check<T: HealthCheckProvider + 'static>(&mut self, check: T) {
        self.checks.push(Box::new(check));
    }

    pub async fn check_all(&self) -> Vec<HealthCheck> {
        let mut results = Vec::new();

        for check in &self.checks {
            let start = Instant::now();
            let (status, message) = check.check().await;
            let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;

            results.push(HealthCheck {
                name: check.name().to_string(),
                status,
                message,
                timestamp: Utc::now(),
                response_time_ms,
            });
        }

        results
    }

    pub async fn overall_status(&self) -> HealthStatus {
        let checks = self.check_all().await;

        if checks.iter().all(|c| c.status == HealthStatus::Healthy) {
            HealthStatus::Healthy
        } else if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else {
            HealthStatus::Degraded
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check provider trait
pub trait HealthCheckProvider: Send + Sync {
    fn name(&self) -> &str;
    fn check(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = (HealthStatus, Option<String>)> + Send + '_>,
    >;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_timer() {
        let timer = PerformanceTimer::start("test_operation".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));
        let duration = timer.stop();
        assert!(duration >= 10.0);
    }

    #[test]
    fn test_in_memory_metrics_collector() {
        let collector = InMemoryMetricsCollector::new();

        collector.increment_counter("test.counter", 5, None);
        collector.increment_counter("test.counter", 3, None);
        assert_eq!(collector.get_counter("test.counter"), Some(8));

        collector.set_gauge("test.gauge", 42.5, None);
        assert_eq!(collector.get_gauge("test.gauge"), Some(42.5));

        collector.record_histogram("test.histogram", 1.0, None);
        collector.record_histogram("test.histogram", 2.0, None);
    }
}
