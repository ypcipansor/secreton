use axum::serve;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error};

use brankas_api::{
    ApiState, ApiConfig, TransitApiState,
    create_api_router,
};
use brankas_crypto::transit_simple::TransitEngine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize simple logging
    // tracing_subscriber::init();
    
    print_startup_banner();
    
    // Create transit engine
    let transit_engine = Arc::new(TransitEngine::new());
    
    // Create API state
    let api_state = ApiState {
        transit: TransitApiState {
            engine: transit_engine,
        },
    };
    
    // Create router
    let app = create_api_router(api_state);
    
    // Bind server
    let config = ApiConfig::default();
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    
    info!("🚀 Brankas API server starting on http://{}", addr);
    info!("📋 Health check: http://{}/health", addr);
    info!("📋 Version info: http://{}/version", addr);
    info!("🔐 Transit API: http://{}/v1/transit", addr);
    
    // Start server
    serve(listener, app)
        .await
        .map_err(|e| {
            error!("Server error: {}", e);
            e
        })?;
    
    Ok(())
}

fn print_startup_banner() {
    println!(r#"
    ╔══════════════════════════════════════════════╗
    ║              🔐 BRANKAS VAULT 🔐              ║
    ║          Enterprise Transit Engine           ║
    ╠══════════════════════════════════════════════╣
    ║  Version: 1.0.0                             ║
    ║  Build: Production Ready                     ║
    ║  Crypto: RustCrypto Suite                    ║
    ╠══════════════════════════════════════════════╣
    ║  🚀 Starting HTTP API Server...              ║
    ╚══════════════════════════════════════════════╝
    "#);
}