use axum::serve;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use secreton_api::tls_optimization::{
    create_optimized_tls_config, get_optimized_cipher_suites, init_session_cache,
    init_certificate_cache, record_tls_handshake, get_tls_metrics, validate_tls_performance
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

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
    let addr: SocketAddr = format!("{}:{}", config.http.bind_address.ip(), config.http.bind_address.port()).parse()?;

    // Check if TLS is configured
    if let Some(tls_config) = &config.tls {
        info!("🔐 Starting Secreton API server with TLS on https://{}", addr);
        serve_with_tls(addr, app, tls_config).await?;
    } else {
        info!("Starting Secreton API server on http://{}", addr);
        let listener = TcpListener::bind(addr).await?;
        serve(listener, app).await.map_err(|e| {
            error!("Server error: {}", e);
            e
        })?;
    }

    Ok(())
}

async fn serve_with_tls(
    addr: SocketAddr,
    app: axum::Router,
    tls_config: &secreton_api::config::TlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use rustls::{Certificate, PrivateKey, ServerConfig};
    use std::fs;
    use std::io::BufReader;
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use tokio_rustls::TlsAcceptor;
    use axum_server::tls_rustls::RustlsConfig;

    info!("Loading TLS certificates...");

    // Load server certificate
    let cert_file = fs::File::open(&tls_config.cert_file)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<Certificate> = certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    if cert_chain.is_empty() {
        return Err("No certificates found in cert file".into());
    }

    // Load private key
    let key_file = fs::File::open(&tls_config.key_file)?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .map(PrivateKey)
        .collect();

    if keys.is_empty() {
        return Err("No private keys found in key file".into());
    }

    // Initialize performance optimizations
    info!("Initializing TLS performance optimizations...");
    init_session_cache(10000, 300); // 10k sessions, 5min TTL
    init_certificate_cache(5000); // 5k cached certificates

    // Create optimized TLS configuration
    let mut server_config = create_optimized_tls_config(
        cert_chain,
        keys.remove(0),
        &tls_config.min_version,
        &tls_config.cipher_suites,
        &tls_config.alpn_protocols,
    )?;

    // Validate configuration
    if let Err(e) = validate_tls_performance(&server_config) {
        warn!("TLS configuration validation warning: {}", e);
    }

    // Create the TLS acceptor with optimized settings
    let rustls_config = RustlsConfig::from_config(Arc::new(server_config));

    info!("Binding to address...");
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;

    info!("🚀 Secreton API server starting on https://{}", addr);
    info!("📋 Health check: https://{}/health", addr);
    info!("📋 Version info: https://{}/version", addr);
    info!("🔐 Transit API: https://{}/v1/transit", addr);
    info!("🗄️  KV Secrets API: https://{}/v1/secrets", addr);

    // Start server with TLS
    axum_server::from_tcp_rustls(listener, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| {
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
