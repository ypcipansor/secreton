use std::env;
use std::sync::Arc;
use tracing::{info, warn};
use warp::Filter;
use secreton_api::config::ApiConfig;
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

// gRPC imports
use tonic::transport::Server;
use secreton_grpc::secreton::v1::secret_service_server::SecretServiceServer;
use secreton_api::grpc::server::GrpcSecretService;

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
    let http_port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");

    let grpc_port = env::var("GRPC_PORT")
        .unwrap_or_else(|_| "50051".to_string())
        .parse::<u16>()
        .expect("GRPC_PORT must be a valid port number");

    info!("Starting Secreton Security API server");
    info!("HTTP Port: {}", http_port);
    info!("gRPC Port: {}", grpc_port);

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
    let mut api_config = match ConfigService::load_config(storage.as_ref()).await {
        Ok(c) => {
            info!("Loaded configuration from storage");
            c
        },
        Err(e) => {
            warn!("Could not load configuration from storage: {}. Using defaults/bootstrapping.", e);
            ApiConfig::default()
        }
    };

    // Ensure JWT secret exists (auto-generate if missing/None)
    if api_config.auth.jwt.secret.is_none() {
        info!("JWT secret not found in configuration. Generating a new secure random secret.");
        let new_secret = uuid::Uuid::new_v4().to_string();
        api_config.auth.jwt.secret = Some(new_secret);

        // Save the updated config back to storage to ensure persistence across restarts
        if let Err(e) = ConfigService::save_config(storage.as_ref(), &api_config).await {
            warn!("Failed to persist generated JWT secret to storage: {}", e);
        } else {
            info!("Persisted generated JWT secret to storage.");
        }
    }

    // Use JWT configuration from stored config
    // We unwrap here safely because we just ensured it is Some
    let jwt_secret = api_config.auth.jwt.secret.clone().unwrap_or_else(|| "fallback-secret-should-not-happen".to_string());
    let jwt_issuer = api_config.auth.jwt.issuer.clone();
    let jwt_audience = api_config.auth.jwt.audience.clone();

    // Initialize Services
    let crypto = Arc::new(CryptoService::new(storage.clone()).await?);

    // Create AuthConfig from loaded config
    let auth_config = api_config.auth.clone();

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

    // Construct HTTP Routes
    let routes = SecurityAPI::routes(storage.clone(), auth.clone(), audit.clone(), seal.clone(), secreton.clone())
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

    // Spawn HTTP Server
    let http_server = warp::serve(routes).run(([127, 0, 0, 1], http_port));

    // Setup gRPC Server
    let grpc_addr = format!("0.0.0.0:{}", grpc_port).parse()?;
    let grpc_service = GrpcSecretService::new(secreton.clone(), auth.clone());

    let grpc_server = Server::builder()
        .add_service(SecretServiceServer::new(grpc_service))
        .serve(grpc_addr);

    info!("🚀 Servers starting...");

    // Run both servers concurrently
    let (http_res, grpc_res) = tokio::join!(http_server, grpc_server);

    if let Err(e) = grpc_res {
        warn!("gRPC server failed: {}", e);
    }

    info!("Servers stopped.");

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
    ║  🚀 Starting API Servers...                  ║
    ╚══════════════════════════════════════════════╝
    "#
    );
}
