//! Secreton server entry point.
//!
//! One process, one listener: the Leptos application, the REST API and — with the `grpc`
//! feature — gRPC all answer on the same port. The previous binary started warp on the
//! configured port, Axum on that port plus ten, and tonic on a third, then joined all
//! three.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;
use secreton_engines::{ServerConfig, Services};
use secreton_server::middleware::rate_limit::RateLimit;
use secreton_server::{build_router, router::AppState, shutdown_signal};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Parser)]
#[command(name = "secreton-server", version, about)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, env = "SECRETON_CONFIG", default_value = "secreton.toml")]
    config: String,

    /// Address to bind. Overrides the configuration file.
    #[arg(long, env = "SECRETON_BIND")]
    bind: Option<SocketAddr>,

    /// Emit logs as JSON rather than human-readable text.
    #[arg(long, env = "SECRETON_LOG_JSON")]
    log_json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_json);

    // Load and validate configuration before touching anything else, so a bad setting
    // stops the process at startup instead of surfacing on a user's first request.
    let mut config = ServerConfig::load(&cli.config)
        .with_context(|| format!("failed to load configuration from {}", cli.config))?;
    if let Some(bind) = cli.bind {
        config.http.bind_address = bind;
    }
    config.validate().context("configuration is invalid")?;

    let services = Services::new(&config)
        .await
        .context("failed to initialise services")?;
    services.start().await;

    let state = AppState {
        rate_limit: RateLimit::new(
            config.rate_limit.global.requests,
            config.http.trusted_proxies,
        ),
        #[cfg(feature = "ui")]
        leptos_options: leptos_options(&config)?,
        services: services.clone(),
    };

    let addr = config.http.bind_address;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    tracing::info!(%addr, "secreton listening");
    tracing::info!("  UI and API   http://{addr}/");
    tracing::info!("  OpenAPI      http://{addr}/api-docs/openapi.json");
    tracing::info!("  Health       http://{addr}/health");
    #[cfg(feature = "grpc")]
    tracing::info!("  gRPC         h2c on the same port");

    let router = build_router(state);

    // `into_make_service_with_connect_info` so the rate limiter can see the peer address
    // when no trusted proxy is configured.
    let served = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    let result = served.await;

    // Drain background workers and flush buffered audit events before exiting. Doing this
    // after the server has stopped accepting means in-flight requests have finished, so
    // no audit event is written after the flush.
    services.shutdown().await;

    result.context("server error")?;
    tracing::info!("shutdown complete");
    Ok(())
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,secreton=debug,tower_http=debug"));

    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        registry.with(tracing_subscriber::fmt::layer()).init();
    }
}

#[cfg(feature = "ui")]
fn leptos_options(config: &ServerConfig) -> Result<leptos::prelude::LeptosOptions> {
    use leptos::config::get_configuration;

    // cargo-leptos writes its settings into the manifest; reading them here keeps the
    // asset paths in one place rather than duplicated between build and runtime.
    let conf = get_configuration(None)
        .context("failed to read the [workspace.metadata.leptos] configuration")?;
    let mut options = conf.leptos_options;
    options.site_addr = config.http.bind_address;
    Ok(options)
}
