//! Health Check System
//!
//! Comprehensive health monitoring for readiness and liveness checks
//! to ensure operational status of all components.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Health status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    /// Component is healthy
    Healthy,

    /// Component is degraded but operational
    Degraded,

    /// Component is unhealthy
    Unhealthy,

    /// Component status is unknown
    Unknown,
}

impl HealthStatus {
    /// Check if status is healthy or degraded (operational)
    pub fn is_operational(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Component name
    pub component: String,

    /// Status
    pub status: HealthStatus,

    /// Message
    pub message: Option<String>,

    /// Response time in milliseconds
    pub response_time_ms: u64,

    /// Checked at
    pub checked_at: DateTime<Utc>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl HealthCheckResult {
    /// Create healthy result
    pub fn healthy(component: String, response_time_ms: u64) -> Self {
        Self {
            component,
            status: HealthStatus::Healthy,
            message: None,
            response_time_ms,
            checked_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create degraded result
    pub fn degraded(component: String, message: String, response_time_ms: u64) -> Self {
        Self {
            component,
            status: HealthStatus::Degraded,
            message: Some(message),
            response_time_ms,
            checked_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create unhealthy result
    pub fn unhealthy(component: String, message: String, response_time_ms: u64) -> Self {
        Self {
            component,
            status: HealthStatus::Unhealthy,
            message: Some(message),
            response_time_ms,
            checked_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }
}

/// Aggregated health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedHealth {
    /// Overall status
    pub status: HealthStatus,

    /// Individual component results
    pub components: HashMap<String, HealthCheckResult>,

    /// Total check duration
    pub duration_ms: u64,

    /// Checked at
    pub checked_at: DateTime<Utc>,
}

/// Health check trait
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    /// Component name
    fn name(&self) -> &str;

    /// Perform health check
    async fn check(&self) -> HealthCheckResult;

    /// Check timeout
    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

/// Storage health check
pub struct StorageHealthCheck {
    name: String,
}

impl StorageHealthCheck {
    pub fn new() -> Self {
        Self {
            name: "storage".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for StorageHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        // Simulate storage check
        tokio::time::sleep(Duration::from_millis(10)).await;

        let elapsed = start.elapsed().as_millis() as u64;
        HealthCheckResult::healthy(self.name.clone(), elapsed)
    }
}

/// Database health check
pub struct DatabaseHealthCheck {
    name: String,
}

impl DatabaseHealthCheck {
    pub fn new() -> Self {
        Self {
            name: "database".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for DatabaseHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        // Simulate database ping
        tokio::time::sleep(Duration::from_millis(20)).await;

        let elapsed = start.elapsed().as_millis() as u64;

        if elapsed > 100 {
            HealthCheckResult::degraded(
                self.name.clone(),
                format!("Slow response: {}ms", elapsed),
                elapsed,
            )
        } else {
            HealthCheckResult::healthy(self.name.clone(), elapsed)
        }
    }
}

/// Cluster health check
pub struct ClusterHealthCheck {
    name: String,
}

impl ClusterHealthCheck {
    pub fn new() -> Self {
        Self {
            name: "cluster".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for ClusterHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        // Simulate cluster status check
        tokio::time::sleep(Duration::from_millis(15)).await;

        let elapsed = start.elapsed().as_millis() as u64;
        HealthCheckResult::healthy(self.name.clone(), elapsed)
    }
}

/// Health service
pub struct HealthService {
    checks: Arc<RwLock<Vec<Arc<dyn HealthCheck>>>>,
    last_check: Arc<RwLock<Option<AggregatedHealth>>>,
}

impl HealthService {
    /// Create new health service
    pub fn new() -> Self {
        Self {
            checks: Arc::new(RwLock::new(Vec::new())),
            last_check: Arc::new(RwLock::new(None)),
        }
    }

    /// Register health check
    pub async fn register(&self, check: Arc<dyn HealthCheck>) {
        let mut checks = self.checks.write().await;
        checks.push(check);
    }

    /// Perform all health checks
    pub async fn check_health(&self) -> AggregatedHealth {
        let start = std::time::Instant::now();
        let checks = self.checks.read().await;

        let mut results = HashMap::new();
        let mut overall_status = HealthStatus::Healthy;

        for check in checks.iter() {
            let timeout = check.timeout();

            let result = match tokio::time::timeout(timeout, check.check()).await {
                Ok(r) => r,
                Err(_) => HealthCheckResult::unhealthy(
                    check.name().to_string(),
                    "Health check timeout".to_string(),
                    timeout.as_millis() as u64,
                ),
            };

            // Determine overall status (worst status wins)
            overall_status = match (overall_status, result.status) {
                (_, HealthStatus::Unhealthy) => HealthStatus::Unhealthy,
                (HealthStatus::Unhealthy, _) => HealthStatus::Unhealthy,
                (_, HealthStatus::Degraded) => HealthStatus::Degraded,
                (HealthStatus::Degraded, _) => HealthStatus::Degraded,
                _ => HealthStatus::Healthy,
            };

            results.insert(check.name().to_string(), result);
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let health = AggregatedHealth {
            status: overall_status,
            components: results,
            duration_ms,
            checked_at: Utc::now(),
        };

        // Update last check
        let mut last = self.last_check.write().await;
        *last = Some(health.clone());

        health
    }

    /// Get last health check result
    pub async fn last_check(&self) -> Option<AggregatedHealth> {
        let last = self.last_check.read().await;
        last.clone()
    }

    /// Check if system is ready (all components operational)
    pub async fn is_ready(&self) -> bool {
        let health = self.check_health().await;
        health.status.is_operational()
    }

    /// Check if system is alive (basic liveness)
    pub async fn is_alive(&self) -> bool {
        true // If we can respond, we're alive
    }
}

impl Default for HealthService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_service() {
        let service = HealthService::new();

        service.register(Arc::new(StorageHealthCheck::new())).await;
        service.register(Arc::new(DatabaseHealthCheck::new())).await;

        let health = service.check_health().await;
        assert_eq!(health.components.len(), 2);
        assert!(health.status.is_operational());
    }

    #[tokio::test]
    async fn test_degraded_status() {
        struct SlowCheck;

        #[async_trait::async_trait]
        impl HealthCheck for SlowCheck {
            fn name(&self) -> &str {
                "slow"
            }

            async fn check(&self) -> HealthCheckResult {
                HealthCheckResult::degraded("slow".to_string(), "Slow response".to_string(), 150)
            }
        }

        let service = HealthService::new();
        service.register(Arc::new(SlowCheck)).await;

        let health = service.check_health().await;
        assert_eq!(health.status, HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_is_ready() {
        let service = HealthService::new();
        service.register(Arc::new(StorageHealthCheck::new())).await;

        assert!(service.is_ready().await);
    }
}
