//! Core server implementation for the API.
//!
//! Handles server startup, configuration, service initialization,
//! and routing setup using the API service container.

use crate::config::ApiConfig;
use crate::handlers::create_router;
use crate::services::ApiServiceContainer;
use std::sync::Arc;
use tracing::info;

/// Main API server structure
pub struct Server {
    config: ApiConfig,
}

impl Server {
    /// Create a new server instance with configuration
    pub fn new(config: ApiConfig) -> Self {
        Self { config }
    }

    /// Run the server
    pub async fn run(self) -> anyhow::Result<()> {
        // Initialize logging
        self.init_logging()?;

        // Create service container
        let services = Arc::new(ApiServiceContainer::new(&self.config).await?);

        // Create router using handler factory
        let app = create_router(&self.config, services);

        // Determine bind address
        let addr = self.config.http.bind_address;
        info!("Server listening on http://{}", addr);

        // Start server
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Initialize logging subsystem
    fn init_logging(&self) -> anyhow::Result<()> {
        // Check if logging already initialized to avoid panic in tests or re-entry
        if tracing_subscriber::fmt::Subscriber::builder().try_init().is_err() {
            // Already initialized, skip
            return Ok(());
        }

        let filter = tracing_subscriber::filter::EnvFilter::new("info")
            .add_directive(self.config.logging.level.parse()?)
            .add_directive("tower_http=info".parse()?);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .init();

        Ok(())
    }
}
