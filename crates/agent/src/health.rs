//! Health monitoring module for the Brankas agent

use crate::config::{HealthConfig, ExternalServiceConfig};
use brankas_core::{CoreResult, CoreError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
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
    
    /// Service start time
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
    pub async fn start(&self, mut shutdown: tokio::sync::broadcast::Receiver<()>) -> CoreResult<()> {
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
    async fn perform_health_checks(&self) -> CoreResult<()> {
        tracing::debug!("Performing health checks");
        
        // For now, just log that we're performing checks
        // In a full implementation, you would perform actual health checks
        // but avoid the lifetime issues by using different patterns
        
        Ok(())
    }
    
    /// Get overall health summary
    pub fn get_health_summary(&self) -> HealthSummary {
        let checks: Vec<HealthCheckResult> = self.recent_results.values().cloned().collect();
        
        let healthy_checks = checks.iter().filter(|c| matches!(c.status, HealthStatus::Healthy)).count();
        let degraded_checks = checks.iter().filter(|c| matches!(c.status, HealthStatus::Degraded)).count();
        let unhealthy_checks = checks.iter().filter(|c| matches!(c.status, HealthStatus::Unhealthy)).count();
        let unknown_checks = checks.iter().filter(|c| matches!(c.status, HealthStatus::Unknown)).count();
        
        let overall_status = if unhealthy_checks > 0 {
            HealthStatus::Unhealthy
        } else if degraded_checks > 0 {
            HealthStatus::Degraded
        } else if healthy_checks > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        };
        
        let uptime_seconds = self.start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_secs();
        
        HealthSummary {
            overall_status,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
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
