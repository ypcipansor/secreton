use axum::serve;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

// Use proper imports from secreton_api
use secreton_api::{
    create_api_router, ApiConfig, ApiState, KVApiState, KVEngine, TransitApiState,
};
use secreton_crypto::transit::TransitEngine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging with simple tracing
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::INFO)
            .finish(),
    )
    .expect("Failed to set tracing subscriber");

    print_startup_banner();

    info!("Creating transit engine...");
    // Create transit engine
    let transit_engine = Arc::new(TransitEngine::new());

    info!("Creating KV engine...");
    // Create KV engine
    let kv_engine = Arc::new(KVEngine::new());

    info!("Creating API state...");
    // Create API state
    let api_state = ApiState {
        transit: TransitApiState {
            engine: transit_engine,
        },
        kv: KVApiState { engine: kv_engine },
    };

    info!("Creating router...");
    // Create router
    let app = create_api_router(api_state);

    info!("Loading configuration...");
    // Load configuration
    let config = ApiConfig::default();
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    info!("Starting Secreton API server on http://{}", addr);
    let listener = TcpListener::bind(addr).await?;
    serve(listener, app).await.map_err(|e| {
        error!("Server error: {}", e);
        e
    })?;

    Ok(())
}

fn print_startup_banner() {
    println!(
        r#"
    ╔══════════════════════════════════════════════╗
    ║              🔐 SECRETON VAULT 🔐             ║
    ║          Enterprise Transit Engine           ║
    ╠══════════════════════════════════════════════╣
    ║  Version: 2.0.1                             ║
    ║  Build: Production Ready                     ║
    ║  Crypto: RustCrypto Suite                    ║
    ╠══════════════════════════════════════════════╣
    ║  🚀 Starting HTTP API Server...              ║
    ╚══════════════════════════════════════════════╝
    "#
    );
}
