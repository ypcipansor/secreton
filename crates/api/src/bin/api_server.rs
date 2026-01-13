use std::env;
use std::sync::Arc;
use tracing::{info, warn};
use warp::Filter;
use secreton_api::config::{ApiConfig, AuthConfig};
use secreton_api::services::config::ConfigService;
use secreton_storage::{StorageFactory, StorageFactoryConfig, StorageBackendType};
use secreton_storage::factory::FileBackendConfig;

// Use the existing security API from lib.rs
use secreton_api::{SecurityAPI, handle_rejection};
use secreton_api::services::crypto::CryptoService;
use secreton_api::services::auth::AuthenticationService;
use secreton_api::services::audit::AuditLogger;
use secreton_api::services::seal::SealService;
use secreton_api::services::secret::SecretService;
use secreton_auth::{InMemoryIdentityService, PolicyService};
use secreton_performance::{SecretPerformanceOptimizer, SecretPerformanceConfig};

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

    // Initialize Storage
    // This part effectively replaces .env dependency for core configuration
    // We bootstrap a storage connection here.
    let storage_config = StorageFactoryConfig {
        backend_type: if let Ok(_path) = env::var("SECRETON_STORAGE_FILE_PATH") {
            StorageBackendType::File
        } else {
             StorageBackendType::Memory
        },
        file_config: env::var("SECRETON_STORAGE_FILE_PATH").ok().map(|p| FileBackendConfig { base_path: p }),
        ..Default::default()
    };

    let storage = StorageFactory::create(storage_config).await?;
    info!("Storage backend initialized");

    // Load Configuration from Storage
    let _api_config = match ConfigService::load_config(storage.as_ref()).await {
        Ok(c) => c,
        Err(e) => {
            warn!("Could not load configuration from storage: {}. Using defaults.", e);
            ApiConfig::default()
        }
    };

    // Load JWT configuration from environment
    let jwt_secret = env::var("SECRETON_JWT_SECRET").unwrap_or_else(|_| "change-this-secret-in-production".to_string());
    let jwt_issuer = env::var("SECRETON_JWT_ISSUER").unwrap_or_else(|_| "secreton".to_string());
    let jwt_audience = env::var("SECRETON_JWT_AUDIENCE").unwrap_or_else(|_| "secreton-api".to_string());

    // Initialize Services
    let crypto = Arc::new(CryptoService::new(storage.clone()).await?);

    // Create AuthConfig with consistent JWT settings
    let mut auth_config = AuthConfig::default();
    auth_config.jwt.secret = jwt_secret.clone();
    auth_config.jwt.issuer = jwt_issuer.clone();
    auth_config.jwt.audience = jwt_audience.clone();

    let auth = Arc::new(AuthenticationService::new(storage.clone(), crypto.clone(), &auth_config).await?);
    let audit = Arc::new(AuditLogger::new(storage.clone()).await?);

    // Initialize Seal Service
    let seal = Arc::new(SealService::new(
        storage.clone(),
        crypto.clone(),
        jwt_secret,
        jwt_issuer,
        jwt_audience
    ));

    // Initialize Secret Service components
    let identity = Arc::new(InMemoryIdentityService::new());
    let policy_service = Arc::new(PolicyService::new());
    let performance = Arc::new(SecretPerformanceOptimizer::new(SecretPerformanceConfig::default()));

    let secreton = Arc::new(SecretService::new(
        storage.clone(),
        crypto.clone(),
        audit.clone(),
        identity,
        policy_service,
        performance
    ).await?);

    // Construct Routes
    let routes = SecurityAPI::routes(storage.clone(), auth, audit, seal, secreton)
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_headers(vec!["content-type", "authorization", "x-session-id", "x-admin-token"])
                .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]),
        )
        .with(warp::log("security_api"))
        .recover(handle_rejection);

    info!("📋 Available endpoints:");
    info!("   GET  /health - System health check");
    info!("   GET  /security/status - Security components status");
    info!("   POST /sys/config - Apply configuration");
    info!("   GET  /sys/config - Read configuration");
    info!("   POST /auth/login - User authentication");

    warp::serve(routes).run(([127, 0, 0, 1], port)).await;

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
