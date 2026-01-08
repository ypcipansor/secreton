use std::env;
use tracing::info;

// Use the existing security API from lib.rs
use secreton_api::start_security_server;

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

    // Get port from environment or default to 8080
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");

    info!("Starting Secreton Security API server on port {}", port);

    // Use the existing start_security_server function from lib.rs
    start_security_server(port).await?;

    Ok(())
}

fn print_startup_banner() {
    println!(
        r#"
    ╔══════════════════════════════════════════════╗
    ║             🔐 SECRETON SERVER 🔐             ║
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
