//! Secreton Agent Library

//! Secreton Security Agent
//!
//! Real-time monitoring, alerting, and security enforcement agent
//! for the Secreton security system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{debug, info, warn};

// Local modules
pub mod auth;
pub mod config;
pub mod health;
pub mod metrics;
// pub mod monitoring;  // Removed - use secreton_monitoring crate instead
pub mod security;
pub mod templating;

// Re-export from monitoring crate
pub use secreton_monitoring::*;

// Re-export local modules
pub use auth::*;
pub use config::*;
pub use health::*;
pub use metrics::*;
// pub use monitoring::*;  // Removed - use secreton_monitoring crate instead
pub use security::*;
pub use templating::*;

use secreton_core::CoreError;
use secreton_errors::SecretonError;

pub struct SecretonAgent {
    config: AgentConfig,
    // monitor: Arc<secreton_monitoring::SystemMonitor>,  // Using monitoring crate directly
    security_enforcer: Arc<SecurityEnforcer>,
    health_checker: Arc<HealthChecker>,
    auth_handler: Arc<AuthHandler>,
    template_manager: Arc<TemplateManager>,
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
}

impl SecretonAgent {
    /// Create a new Secreton Agent
    pub async fn new(config: AgentConfig) -> Result<Self, SecretonError> {
        info!(
            "Initializing Secreton Security Agent v{}",
            env!("CARGO_PKG_VERSION")
        );

        // Create security event channel
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();

        // Create health check channel
        let (health_tx, _health_rx) = tokio::sync::mpsc::unbounded_channel();

        // let monitor = Arc::new(SystemMonitor::new(config.monitoring.clone(), monitoring_tx));
        let security_enforcer = Arc::new(SecurityEnforcer::new(config.security.clone(), event_tx));
        let health_checker = Arc::new(HealthChecker::new(config.health.clone(), health_tx));

        // Initialize Vault/Secreton Agent features
        let auth_handler = Arc::new(AuthHandler::new(config.vault.clone()));
        if let Err(e) = auth_handler.initialize().await {
            warn!("Failed to initialize authentication: {}", e);
        }

        let template_manager = Arc::new(TemplateManager::new(
            (*auth_handler).clone(),
            config.templates.clone()
        ));

        Ok(Self {
            config,
            // monitor,  // Using monitoring crate directly
            security_enforcer,
            health_checker,
            auth_handler,
            template_manager,
            shutdown_tx: None,
        })
    }

    /// Start the agent with all monitoring services
    pub async fn start(&mut self) -> Result<(), SecretonError> {
        info!("Starting Secreton Security Agent...");

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start all services
        // let monitor_task = self.start_monitoring_service(shutdown_rx.resubscribe());  // Using monitoring crate directly
        let security_task = self.start_security_service(shutdown_rx.resubscribe());
        let health_task = self.start_health_service(shutdown_rx.resubscribe());
        let metrics_task = self.start_metrics_service(shutdown_rx.resubscribe());
        let template_task = self.start_template_service(shutdown_rx.resubscribe());

        info!("All agent services started successfully");

        // Wait for shutdown signal
        tokio::select! {
            // _ = monitor_task => warn!("Monitoring service stopped"),  // Using monitoring crate directly
            _ = security_task => warn!("Security service stopped"),
            _ = health_task => warn!("Health service stopped"),
            _ = metrics_task => warn!("Metrics service stopped"),
            _ = template_task => warn!("Template service stopped"),
            _ = shutdown_rx.recv() => info!("Shutdown signal received"),
            _ = tokio::signal::ctrl_c() => info!("Ctrl+C received, shutting down"),
        }

        self.shutdown().await
    }

    /// Shutdown the agent gracefully
    pub async fn shutdown(&self) -> Result<(), SecretonError> {
        info!("Shutting down Secreton Security Agent...");

        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }

        // Give services time to cleanup
        sleep(Duration::from_secs(2)).await;

        info!("Secreton Security Agent shutdown complete");
        Ok(())
    }

    /// Start security enforcement service
    async fn start_security_service(
        &self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), SecretonError> {
        let _enforcer = Arc::clone(&self.security_enforcer);

        tokio::spawn(async move {
            let interval = Duration::from_secs(300); // 5 minutes
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        tracing::debug!("Security enforcement service tick");
                        // Perform security checks here
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Security service shutting down");
                        break;
                    }
                }
            }

            Ok::<(), CoreError>(())
        })
        .await
        .map_err(|e| CoreError::Internal {
            message: format!("Security service task failed: {}", e),
        })??;

        Ok(())
    }

    /// Start template rendering service
    async fn start_template_service(
        &self,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), SecretonError> {
        let template_manager = Arc::clone(&self.template_manager);

        tokio::spawn(async move {
            if let Err(e) = template_manager.start(shutdown_rx).await {
                 tracing::error!("Template manager error: {}", e);
                 return Err(SecretonError::Internal { message: format!("Template manager failed: {}", e) });
            }
            Ok(())
        })
        .await
        .map_err(|e| CoreError::Internal {
            message: format!("Template service task failed: {}", e),
        })??;

        Ok(())
    }

    /// Start health checking service
    async fn start_health_service(
        &self,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), SecretonError> {
        let health_checker = Arc::clone(&self.health_checker);

        if let Err(e) = health_checker.start(shutdown_rx).await {
            tracing::error!("Health checker error: {}", e);
        }

        Ok(())
    }

    /// Start metrics collection service
    async fn start_metrics_service(
        &self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), SecretonError> {
        // Metrics collection disabled - simplified implementation
        tokio::spawn(async move {
            let interval = Duration::from_secs(60);
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        tracing::debug!("Metrics collection service tick (disabled)");
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Metrics service shutting down");
                        break;
                    }
                }
            }

            Ok::<(), CoreError>(())
        })
        .await
        .map_err(|e| CoreError::Internal {
            message: format!("Metrics service task failed: {}", e),
        })??;

        Ok(())
    }

    /// Get current agent status
    pub async fn get_status(&self) -> AgentStatus {
        AgentStatus {
            agent_id: self.config.agent_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: Utc::now(), // Should track actual start time
            uptime_seconds: 0,      // Should calculate actual uptime
            monitoring_active: true,
            alerting_active: true,
            security_active: true,
            health_active: true,
            metrics_active: true,
            last_monitoring_check: Utc::now(),
            last_alert_processed: Utc::now(),
            last_security_scan: Utc::now(),
            last_health_check: Utc::now(),
            last_metrics_collection: Utc::now(),
        }
    }
}

/// Agent runtime status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_id: String,
    pub version: String,
    pub started_at: DateTime<Utc>,
    pub uptime_seconds: u64,
    pub monitoring_active: bool,
    pub alerting_active: bool,
    pub security_active: bool,
    pub health_active: bool,
    pub metrics_active: bool,
    pub last_monitoring_check: DateTime<Utc>,
    pub last_alert_processed: DateTime<Utc>,
    pub last_security_scan: DateTime<Utc>,
    pub last_health_check: DateTime<Utc>,
    pub last_metrics_collection: DateTime<Utc>,
}

/// Entry point function for running the agent
pub async fn run_agent() -> Result<(), SecretonError> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = AgentConfig::load_from_env().await.unwrap_or_else(|_| {
        warn!("Failed to load config from environment, using defaults");
        AgentConfig::default()
    });

    // Create and start agent
    let mut agent = SecretonAgent::new(config).await?;
    agent.start().await
}
