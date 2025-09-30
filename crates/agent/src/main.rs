use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod collector;
mod config;
mod metrics;
mod monitor;

use config::AgentConfig;
use metrics::MetricsServer;
use monitor::SystemMonitor;

#[derive(Debug, Serialize, Deserialize)]
struct AgentStatus {
    version: String,
    uptime: Duration,
    status: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Starting Brankas Monitoring Agent");

    // Load configuration
    let config = AgentConfig::load().await?;
    info!("Configuration loaded successfully");

    // Initialize metrics server
    let metrics_server = MetricsServer::new(config.metrics_port()).await?;
    let metrics_handle = tokio::spawn(async move {
        if let Err(e) = metrics_server.serve().await {
            error!("Metrics server error: {}", e);
        }
    });

    // Initialize system monitor
    let mut system_monitor = SystemMonitor::new(&config).await?;

    // Start monitoring loop
    let mut collection_interval = interval(Duration::from_secs(config.collection_interval()));
    let mut report_interval = interval(Duration::from_secs(config.report_interval()));

    info!(
        "Agent started successfully, collecting metrics every {}s",
        config.collection_interval()
    );

    loop {
        tokio::select! {
            _ = collection_interval.tick() => {
                if let Err(e) = system_monitor.collect_metrics().await {
                    error!("Failed to collect metrics: {}", e);
                }
            }
            _ = report_interval.tick() => {
                if let Err(e) = system_monitor.report_status().await {
                    warn!("Failed to report status: {}", e);
                }
            }
            // Graceful shutdown
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, stopping agent");
                break;
            }
        }
    }

    // Wait for metrics server to finish
    metrics_handle.abort();
    info!("Brankas Monitoring Agent stopped");

    Ok(())
}
