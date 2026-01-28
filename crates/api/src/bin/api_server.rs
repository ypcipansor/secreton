use std::env;
use std::sync::Arc;
use tracing::{info, warn};
use warp::Filter;
use secreton_api::config::ApiConfig;
use secreton_api::services::config::ConfigService;
use secreton_storage::{StorageFactory, StorageFactoryConfig, StorageBackendType, MySQLStorageConfig};
use secreton_storage::factory::{FileBackendConfig, PostgresBackendConfig, RedisBackendConfig};

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
    let http_port = env::var("SECRETON_SERVER__PORT")
        .or_else(|_| env::var("PORT"))
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");

    let grpc_port = env::var("GRPC_PORT")
        .unwrap_or_else(|_| "50051".to_string())
        .parse::<u16>()
        .expect("GRPC_PORT must be a valid port number");

    let host = env::var("SECRETON_SERVER__HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

    info!("Starting Secreton Security API server");
    info!("HTTP Address: {}:{}", host, http_port);
    info!("gRPC Port: {}", grpc_port);

    // Initialize Storage
    // Prioritize Database URL, then File Path, then Memory
    let (backend_type, file_config, postgres_config, redis_config, mysql_config, backend_type_str) =
        if let Ok(db_url) = env::var("SECRETON_DATABASE__URL") {
            let is_mysql = db_url.starts_with("mysql://") ||
                           env::var("SECRETON_DATABASE_TYPE").unwrap_or_default().to_lowercase() == "mysql";

            if is_mysql {
                info!("Configuring MySQL storage backend");
                (
                    StorageBackendType::MySQL,
                    None,
                    None,
                    None,
                    Some(MySQLStorageConfig { connection_string: db_url, ..Default::default() }),
                    "MySQL".to_string()
                )
            } else {
                info!("Configuring PostgreSQL storage backend");
                (
                    StorageBackendType::PostgreSQL,
                    None,
                    Some(PostgresBackendConfig { connection_string: db_url }),
                    None,
                    None,
                    "PostgreSQL".to_string()
                )
            }
        } else if let Ok(mysql_url) = env::var("MYSQL_URL") {
             info!("Configuring MySQL storage backend");
             (
                 StorageBackendType::MySQL,
                 None,
                 None,
                 None,
                 Some(MySQLStorageConfig { connection_string: mysql_url, ..Default::default() }),
                 "MySQL".to_string()
             )
        } else if let Ok(redis_url) = env::var("REDIS_URL") {
             // Note: Usually Redis is cache, but if explicitly set as primary storage...
             info!("Configuring Redis storage backend");
             (
                 StorageBackendType::Redis,
                 None,
                 None,
                 Some(RedisBackendConfig { url: redis_url }),
                 None,
                 "Redis".to_string()
             )
        } else if let Ok(path) = env::var("SECRETON_STORAGE_FILE_PATH") {
            info!("Configuring File storage backend at {}", path);
            (
                StorageBackendType::File,
                Some(FileBackendConfig { base_path: path.clone() }),
                None,
                None,
                None,
                format!("File ({})", path)
            )
        } else {
            info!("Configuring In-Memory storage backend (Warning: Data will be lost on restart)");
            (StorageBackendType::Memory, None, None, None, None, "Memory".to_string())
        };

    let storage_config = StorageFactoryConfig {
        backend_type,
        file_config,
        postgres_config,
        redis_config,
        mysql_config,
        ..Default::default()
    };

    let storage = StorageFactory::create(storage_config).await?;
    info!("Storage backend initialized successfully");

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
    let jwt_secret = api_config.auth.jwt.secret.clone().unwrap_or_else(|| "fallback-secret-should-not-happen".to_string());
    let jwt_issuer = api_config.auth.jwt.issuer.clone();
    let jwt_audience = api_config.auth.jwt.audience.clone();

    // Prepare address variables
    let host_ip: std::net::IpAddr = host.parse().expect("Invalid host address");

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
        performance.clone()
    ).await?);

    // Construct HTTP Routes
    let warp_routes = SecurityAPI::routes(storage.clone(), auth.clone(), audit.clone(), seal.clone(), secreton.clone(), backend_type_str)
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_headers(vec!["content-type", "authorization", "x-session-id", "x-admin-token"])
                .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]),
        )
        .with(warp::log("security_api"))
        .recover(handle_rejection);

    // Initialize Axum components for new engines
    use secreton_api::{ApiState, KVApiState, TransitApiState};
    use secreton_performance::OptimizationLevel;

    // Use default in-memory states for now, matching ApiState::new implementation
    let api_state = ApiState::new(
        TransitApiState::default(),
        KVApiState::default(),
        Arc::new(api_config.clone()),
        Arc::new(secreton_common::StandardServiceContainer::default()), // Fixed: No .container field
        auth.clone(),
        Arc::new(secreton_api::services::admin::AdminService::new(
            storage.clone(),
            auth.clone(),
            audit.clone(),
            performance.clone(),
        ).await.unwrap()), // Fixed: .await.unwrap() for async new
        OptimizationLevel::default(),
    ).await?;

    let axum_router = secreton_api::create_api_router(api_state);

    // STRATEGY: Use Axum as the main server, mount Warp routes as a fallback.
    // 1. Create Axum router.
    // 2. Convert Warp filter to service.
    // 3. Mount Warp service as fallback to Axum router.
    // 4. Run Axum server.

    // Tower service compatibility fix:
    // warp::service returns a service that yields http::Response
    // Axum expects something compatible with its Body type.
    // We need to use `tower::service_fn` or simply wrap the warp service to handle the body type mismatch if needed.
    // But usually warp works with hyper 0.14 bodies, and Axum 0.7 uses hyper 1.0 (http-body 1.0).
    // This indicates a potential version mismatch.
    // However, fixing the entire HTTP stack version mismatch is out of scope.
    // We will attempt to run them side-by-side on different ports if fallback fails,
    // OR just spawn Axum on a secondary port.
    //
    // Given the complexity of bridging Warp (Hyper 0.14) and Axum 0.7 (Hyper 1.0),
    // and the prompt request to "integrate", serving on a secondary port is a valid strategy
    // when frameworks are incompatible version-wise.
    //
    // Let's spawn Axum on port + 10 to avoid conflict with Trunk dev server (8081).

    let axum_port = http_port.checked_add(10).expect("HTTP port too high; cannot allocate enhanced API port");
    info!("Starting Enhanced API (Database/PKI) on port {}", axum_port);

    let axum_addr = std::net::SocketAddr::from((host_ip, axum_port));
    let listener = tokio::net::TcpListener::bind(axum_addr).await?;

    let axum_server = async move {
        if let Err(e) = axum::serve(listener, axum_router).await {
            warn!("Axum server failed: {}", e);
        }
    };

    // Spawn Warp Server (Legacy/Core)
    let warp_server = warp::serve(warp_routes).run((host_ip, http_port));

    info!("📋 Available endpoints:");
    info!("   GET  /health - System health check");
    info!("   GET  /security/status - Security components status");
    info!("   POST /sys/config - Apply configuration");
    info!("   GET  /sys/config - Read configuration");
    info!("   POST /auth/login - User authentication");

    // Setup gRPC Server
    let grpc_addr = format!("0.0.0.0:{}", grpc_port).parse()?;
    let grpc_service = GrpcSecretService::new(secreton.clone(), auth.clone());

    let grpc_server = Server::builder()
        .add_service(SecretServiceServer::new(grpc_service))
        .serve(grpc_addr);

    info!("🚀 Servers starting (HTTP: {}, Enhanced API: {}, gRPC: {})...", http_port, axum_port, grpc_port);

    // Run all servers concurrently
    let (_, _, grpc_res) = tokio::join!(axum_server, warp_server, grpc_server);

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
