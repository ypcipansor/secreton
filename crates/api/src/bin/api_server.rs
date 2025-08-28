use axum::serve;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::error;

use secreton_api::{create_api_router, ApiConfig, ApiState, KVApiState, TransitApiState};
use secreton_crypto::{transit_simple::TransitEngine, KVEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize simple logging
    // tracing_subscriber::init();

    print_startup_banner();

    println!("Creating transit engine...");
    // Create transit engine
    let transit_engine = Arc::new(TransitEngine::new());

    println!("Creating KV engine...");
    // Create KV engine
    let kv_engine = Arc::new(KVEngine::new());

    println!("Creating API state...");
    // Create API state
    let api_state = ApiState {
        transit: TransitApiState {
            engine: transit_engine,
        },
        kv: KVApiState { engine: kv_engine },
    };

    println!("Creating router...");
    // Create router
    let app = create_api_router(api_state);

    println!("Binding to address...");
    // Bind server
    let config = ApiConfig::default();
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    println!("🚀 Secreton API server starting on http://{}", addr);
    println!("📋 Health check: http://{}/health", addr);
    println!("📋 Version info: http://{}/version", addr);
    println!("🔐 Transit API: http://{}/v1/transit", addr);
    println!("🗄️  KV Secrets API: http://{}/v1/secrets", addr);

    // Start server
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
