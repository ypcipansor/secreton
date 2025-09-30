//! Metrics collector module for the Brankas agent

use crate::config::AgentConfig;
use crate::metrics::MetricPoint;
use secreton_core::CoreResult;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Metrics collector for gathering system metrics
#[allow(dead_code)]
pub struct MetricsCollector {
    config: Arc<AgentConfig>,
    metrics_tx: mpsc::UnboundedSender<MetricPoint>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    #[allow(dead_code)]
    pub fn new(config: &AgentConfig) -> CoreResult<Self> {
        let (metrics_tx, _metrics_rx) = mpsc::unbounded_channel();

        Ok(Self {
            config: Arc::new(config.clone()),
            metrics_tx,
        })
    }

    /// Start collecting metrics
    #[allow(dead_code)]
    pub async fn start_collection(&mut self) -> CoreResult<()> {
        tracing::info!("Starting metrics collection");
        Ok(())
    }

    /// Stop collecting metrics
    #[allow(dead_code)]
    pub async fn stop_collection(&mut self) -> CoreResult<()> {
        tracing::info!("Stopping metrics collection");
        Ok(())
    }
}
