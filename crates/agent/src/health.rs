//! Health monitoring module for the Secreton agent

use crate::config::HealthConfig;
use secreton_domain::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Health status levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "Healthy"),
            HealthStatus::Degraded => write!(f, "Degraded"),
            HealthStatus::Unhealthy => write!(f, "Unhealthy"),
            HealthStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub timestamp: u64,
    pub response_time_ms: Option<u64>,
    pub details: HashMap<String, String>,
}

impl HealthCheckResult {
    pub fn new(name: String, status: HealthStatus, message: String) -> Self {
        Self {
            name,
            status,
            message,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            response_time_ms: None,
            details: HashMap::new(),
        }
    }

    pub fn with_response_time(mut self, response_time_ms: u64) -> Self {
        self.response_time_ms = Some(response_time_ms);
        self
    }

    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }
}

/// Overall health summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub overall_status: HealthStatus,
    pub timestamp: u64,
    pub healthy_checks: usize,
    pub degraded_checks: usize,
    pub unhealthy_checks: usize,
    pub unknown_checks: usize,
    pub checks: Vec<HealthCheckResult>,
    pub uptime_seconds: u64,
    pub agent_version: String,
}

/// Health checker service
#[derive(Debug)]
pub struct HealthChecker {
    /// Configuration
    config: HealthConfig,

    /// Channel for sending health results
    health_sender: mpsc::UnboundedSender<HealthCheckResult>,

    /// HTTP client for external checks
    http_client: reqwest::Client,

    /// Recent health check results
    recent_results: HashMap<String, HealthCheckResult>,

    start_time: SystemTime,

    /// Running flag
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(
        config: HealthConfig,
        health_sender: mpsc::UnboundedSender<HealthCheckResult>,
    ) -> Self {
        Self {
            config,
            health_sender,
            http_client: reqwest::Client::new(),
            recent_results: HashMap::new(),
            start_time: SystemTime::now(),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Main health monitoring loop
    pub async fn start(
        &self,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), SecretonError> {
        tracing::info!("Starting health checker");

        let check_interval = Duration::from_secs(self.config.check_interval_seconds);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(check_interval) => {
                    if let Err(e) = self.perform_health_checks().await {
                        tracing::error!("Health check failed: {}", e);
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("Health checker shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Perform all health checks
    async fn perform_health_checks(&self) -> Result<(), SecretonError> {
        tracing::debug!("Performing health checks");

        // Perform basic health checks
        self.check_memory_usage().await?;
        self.check_disk_usage().await?;
        self.check_network_connectivity().await?;

        Ok(())
    }

    /// Check memory usage
    async fn check_memory_usage(&self) -> Result<(), SecretonError> {
        let memory = sysinfo::System::new_all();
        let total_memory = memory.total_memory() as f64;
        let used_memory = memory.used_memory() as f64;

        if total_memory > 0.0 {
            let usage_percent = (used_memory / total_memory) * 100.0;
            let status = if usage_percent > 90.0 {
                HealthStatus::Unhealthy
            } else if usage_percent > 80.0 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Healthy
            };

            let result = HealthCheckResult {
                name: "memory_usage".to_string(),
                status,
                message: format!("Memory usage: {:.1}%", usage_percent),
                timestamp: unix_secs_source().as_secs(),
                response_time_ms: None,
                details: {
                    let mut map = HashMap::new();
                    map.insert(
                        "total_mb".to_string(),
                        format!("{:.1}", total_memory / 1024.0 / 1024.0),
                    );
                    map.insert(
                        "used_mb".to_string(),
                        format!("{:.1}", used_memory / 1024.0 / 1024.0),
                    );
                    map.insert("usage_percent".to_string(), format!("{:.1}", usage_percent));
                    map
                },
            };

            let _ = self.health_sender.send(result);
        }

        Ok(())
    }

    /// Check disk usage
    async fn check_disk_usage(&self) -> Result<(), SecretonError> {
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();

        for disk in disks.iter() {
            let total_space = disk.total_space() as f64;
            let available_space = disk.available_space() as f64;

            if total_space > 0.0 {
                let used_space = total_space - available_space;
                let usage_percent = (used_space / total_space) * 100.0;

                let status = if usage_percent > 95.0 {
                    HealthStatus::Unhealthy
                } else if usage_percent > 90.0 {
                    HealthStatus::Degraded
                } else {
                    HealthStatus::Healthy
                };

                let mount_point = disk.mount_point().to_string_lossy();

                let result = HealthCheckResult {
                    name: format!("disk_usage_{}", mount_point),
                    status,
                    message: format!("Disk usage ({}): {:.1}%", mount_point, usage_percent),
                    timestamp: unix_secs_source().as_secs(),
                    response_time_ms: None,
                    details: {
                        let mut map = HashMap::new();
                        map.insert("mount_point".to_string(), mount_point.to_string());
                        map.insert(
                            "total_gb".to_string(),
                            format!("{:.1}", total_space / 1024.0 / 1024.0 / 1024.0),
                        );
                        map.insert(
                            "available_gb".to_string(),
                            format!("{:.1}", available_space / 1024.0 / 1024.0 / 1024.0),
                        );
                        map.insert("usage_percent".to_string(), format!("{:.1}", usage_percent));
                        map
                    },
                };

                let _ = self.health_sender.send(result);
            }
        }

        Ok(())
    }

    /// Check network connectivity
    async fn check_network_connectivity(&self) -> Result<(), SecretonError> {
        // Simple connectivity check to a reliable endpoint
        match self
            .http_client
            .get("https://www.google.com")
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let result = HealthCheckResult {
                    name: "network_connectivity".to_string(),
                    status: HealthStatus::Healthy,
                    message: "Network connectivity is healthy".to_string(),
                    timestamp: unix_secs_source().as_secs(),
                    response_time_ms: None,
                    details: HashMap::new(),
                };
                let _ = self.health_sender.send(result);
            }
            Ok(_) => {
                let result = HealthCheckResult {
                    name: "network_connectivity".to_string(),
                    status: HealthStatus::Degraded,
                    message: "Network connectivity has issues".to_string(),
                    timestamp: unix_secs_source().as_secs(),
                    response_time_ms: None,
                    details: HashMap::new(),
                };
                let _ = self.health_sender.send(result);
            }
            Err(e) => {
                let result = HealthCheckResult {
                    name: "network_connectivity".to_string(),
                    status: HealthStatus::Unhealthy,
                    message: format!("Network connectivity failed: {}", e),
                    timestamp: unix_secs_source().as_secs(),
                    response_time_ms: None,
                    details: HashMap::new(),
                };
                let _ = self.health_sender.send(result);
            }
        }

        Ok(())
    }

    /// Get overall health summary
    pub fn get_health_summary(&self) -> HealthSummary {
        let checks: Vec<HealthCheckResult> = self.recent_results.values().cloned().collect();

        let healthy_checks = checks
            .iter()
            .filter(|c| matches!(c.status, HealthStatus::Healthy))
            .count();
        let degraded_checks = checks
            .iter()
            .filter(|c| matches!(c.status, HealthStatus::Degraded))
            .count();
        let unhealthy_checks = checks
            .iter()
            .filter(|c| matches!(c.status, HealthStatus::Unhealthy))
            .count();
        let unknown_checks = checks
            .iter()
            .filter(|c| matches!(c.status, HealthStatus::Unknown))
            .count();

        let overall_status = if unhealthy_checks > 0 {
            HealthStatus::Unhealthy
        } else if degraded_checks > 0 {
            HealthStatus::Degraded
        } else if healthy_checks > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        };

        let uptime_seconds = self
            .start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_secs();

        HealthSummary {
            overall_status,
            timestamp: unix_secs_source().as_secs(),
            healthy_checks,
            degraded_checks,
            unhealthy_checks,
            unknown_checks,
            checks,
            uptime_seconds,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Get specific health check result
    pub fn get_health_check(&self, name: &str) -> Option<&HealthCheckResult> {
        self.recent_results.get(name)
    }

    /// Check if health checker is running
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

/// Seconds since the Unix epoch, saturating at 0.
///
/// `duration_since(UNIX_EPOCH).unwrap()` panics on a host whose clock predates 1970.
/// A health reporter is the last component that should take the process down.
fn unix_secs_source() -> std::time::Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
}
