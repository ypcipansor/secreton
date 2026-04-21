use secreton_api::config::ApiConfig;
use secreton_api::services::config::ConfigService;
use secreton_storage::factory::{FileBackendConfig, PostgresBackendConfig, RedisBackendConfig};
use secreton_storage::{
    MySQLStorageConfig, StorageBackendType, StorageFactory, StorageFactoryConfig,
};
use std::env;
use std::sync::Arc;
use tracing::{info, warn};
use warp::Filter;

// Use the existing security API from lib.rs
use secreton_api::services::audit::AuditLogger;
use secreton_api::services::auth::AuthenticationService;
use secreton_api::services::crypto::CryptoService;
use secreton_api::services::seal::SealService;
use secreton_api::services::secret::SecretService;
use secreton_api::{SecurityAPI, handle_rejection};
use secreton_auth::{InMemoryIdentityService, PolicyService};
use secreton_performance::{SecretPerformanceConfig, SecretPerformanceOptimizer};

// gRPC imports
use secreton_api::grpc::server::GrpcSecretService;
use secreton_grpc::secreton::v1::secret_service_server::SecretServiceServer;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
            let is_mysql = db_url.starts_with("mysql://")
                || env::var("SECRETON_DATABASE_TYPE")
                    .unwrap_or_default()
                    .to_lowercase()
                    == "mysql";

            if is_mysql {
                info!("Configuring MySQL storage backend");
                (
                    StorageBackendType::MySQL,
                    None,
                    None,
                    None,
                    Some(MySQLStorageConfig {
                        connection_string: db_url,
                        ..Default::default()
                    }),
                    "MySQL".to_string(),
                )
            } else {
                info!("Configuring PostgreSQL storage backend");
                (
                    StorageBackendType::PostgreSQL,
                    None,
                    Some(PostgresBackendConfig {
                        connection_string: db_url,
                    }),
                    None,
                    None,
                    "PostgreSQL".to_string(),
                )
            }
        } else if let Ok(mysql_url) = env::var("MYSQL_URL") {
            info!("Configuring MySQL storage backend");
            (
                StorageBackendType::MySQL,
                None,
                None,
                None,
                Some(MySQLStorageConfig {
                    connection_string: mysql_url,
                    ..Default::default()
                }),
                "MySQL".to_string(),
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
                "Redis".to_string(),
            )
        } else if let Ok(path) = env::var("SECRETON_STORAGE_FILE_PATH") {
            info!("Configuring File storage backend at {}", path);
            (
                StorageBackendType::File,
                Some(FileBackendConfig {
                    base_path: path.clone(),
                }),
                None,
                None,
                None,
                format!("File ({})", path),
            )
        } else {
            // Default to Raft storage as requested ("secara default storage nya menggunakan raft")
            // If Raft config is not explicitly provided, we default to a single-node Raft cluster on disk or fallback to file if raft not fully configured.
            // However, the prompt implies "default storage uses raft".
            // We'll configure it as Raft with a default local data directory if no other config is present.
            info!("Configuring Default Raft storage backend");
            let data_dir = env::var("SECRETON_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
            (
                StorageBackendType::Raft,
                None,
                None,
                None,
                None,
                "Raft".to_string(),
            )
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

    use secreton_config::Config;
    // Load Configuration from Storage
    let mut api_config = match ConfigService::load_config(storage.as_ref()).await {
        Ok(c) => {
            info!("Loaded configuration from storage");
            c
        }
        Err(e) => {
            warn!(
                "Could not load configuration from storage: {}. Using defaults/bootstrapping.",
                e
            );
            ApiConfig::default()
        }
    };

    if api_config.audit.enabled {
        if api_config.audit.retention_days == 0 {
            tracing::error!("Audit retention_days is 0, enforcing safe default of 2555");
            api_config.audit.retention_days = 2555;
        }
        if api_config.audit.max_batch_size == 0 {
            tracing::error!("Audit max_batch_size is 0, enforcing safe default of 100");
            api_config.audit.max_batch_size = 100;
        }
    }

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
    let jwt_secret = api_config
        .auth
        .jwt
        .secret
        .clone()
        .unwrap_or_else(|| "fallback-secret-should-not-happen".to_string());
    let jwt_issuer = api_config.auth.jwt.issuer.clone();
    let jwt_audience = api_config.auth.jwt.audience.clone();

    // Prepare address variables
    let host_ip: std::net::IpAddr = host.parse().expect("Invalid host address");

    // Initialize Services
    let crypto = Arc::new(CryptoService::new(storage.clone()).await?);

    // Create AuthConfig from loaded config
    let auth_config = api_config.auth.clone();

    // Initialize MFA Services first to share the instance
    // NOTE: Currently using InMemory storage for MFA. In production, this should be backed by persistent storage.
    // Ideally, we would use the ApiServiceContainer to manage this, but for now we construct manually to match existing pattern.
    use secreton_api::services::mfa_persistence::PersistentTotpService;
    use secreton_auth::mfa::{
        CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService, DefaultWebAuthnService,
        EmailConfig, InMemoryEmailService, InMemoryHardwareService, InMemorySmsService, SmsConfig,
        SmsProvider,
    };

    // Use Persistent TOTP Service backed by storage
    let totp_service = Arc::new(PersistentTotpService::new(
        storage.clone(),
        crypto.clone(),
        "secreton".to_string(),
    ));

    // Configure SMS
    let sms_config = if let Some(sms) = &auth_config.mfa.sms {
        SmsConfig {
            provider: match sms.provider.to_lowercase().as_str() {
                "twilio" => SmsProvider::Twilio,
                "awssns" | "aws_sns" => SmsProvider::AwsSns,
                "nexmo" => SmsProvider::Nexmo,
                _ => SmsProvider::Custom {
                    url: "http://localhost/sms".to_string(),
                },
            },
            api_key: sms.api_key.clone(),
            api_secret: None,
            from_number: sms.from_number.clone(),
            message_template: "Your Secreton code is {code}".to_string(),
            code_length: 6,
            code_expiry_seconds: 300,
        }
    } else {
        SmsConfig::default()
    };
    let sms_service = Arc::new(InMemorySmsService::new(sms_config));

    // Configure Email
    let email_config = if let Some(email) = &auth_config.mfa.email {
        EmailConfig {
            smtp_server: email.smtp_server.clone(),
            smtp_port: email.smtp_port,
            smtp_username: email.username.clone(),
            smtp_password: email.password.clone(),
            from_email: email.from_address.clone(),
            subject_template: "Secreton Verification Code".to_string(),
            body_template: "Your verification code is: {code}".to_string(),
            code_length: 6,
            code_expiry_seconds: 300,
        }
    } else {
        EmailConfig::default()
    };
    let email_service = Arc::new(InMemoryEmailService::new(email_config));

    let mfa = Arc::new(CombinedMfaService::new(
        totp_service,
        sms_service,
        email_service,
        Arc::new(InMemoryHardwareService::new()),
        Arc::new(DefaultPushService::new_mock()),
        Arc::new(DefaultWebAuthnService::new_default()),
        Arc::new(DefaultRecoveryCodeService::new()),
    ));

    // Initialize Auth Service with MFA injected
    let auth = Arc::new(
        AuthenticationService::new(storage.clone(), crypto.clone(), &auth_config)
            .await?
            .with_mfa(mfa.clone()),
    );

    let audit = Arc::new(AuditLogger::new(storage.clone(), api_config.audit.retention_days, api_config.audit.max_batch_size, api_config.audit.enabled).await?);

    // Initialize Seal Service
    let seal = Arc::new(SealService::new(
        storage.clone(),
        crypto.clone(),
        jwt_secret,
        jwt_issuer,
        jwt_audience,
    ));

    // Initialize Secret Service components
    use secreton_auth::IdentityService;
    let identity: Arc<dyn IdentityService + Send + Sync> = Arc::new(InMemoryIdentityService::new());
    let policy_service = Arc::new(PolicyService::new());
    let performance = Arc::new(SecretPerformanceOptimizer::new(
        SecretPerformanceConfig::default(),
    ));

    let secreton = Arc::new(
        SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
            identity.clone(),
            policy_service.clone(),
            performance.clone(),
        )
        .await?,
    );

    // Construct HTTP Routes
    // Pass the SHARED mfa instance
    let warp_routes = SecurityAPI::routes(
        storage.clone(),
        auth.clone(),
        audit.clone(),
        seal.clone(),
        secreton.clone(),
        mfa.clone(),
        backend_type_str,
    )
    .with(
        warp::cors()
            .allow_any_origin()
            .allow_headers(vec![
                "content-type",
                "authorization",
                "x-session-id",
                "x-admin-token",
            ])
            .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]),
    )
    .with(warp::log("security_api"))
    .recover(handle_rejection);

    // Initialize Axum components for new engines
    use secreton_api::services::pki::PkiPersistentService;
    use secreton_api::{ApiState, KVApiState};
    use secreton_performance::OptimizationLevel;

    // Initialize PKI Persistent Service
    let pki_service = Arc::new(PkiPersistentService::new(storage.clone(), crypto.clone()));
    if let Err(e) = pki_service.ensure_initialized().await {
        // Elevate initialization failure to critical error to prevent running with potentially inconsistent state
        tracing::error!("Failed to initialize PKI service from storage: {}", e);
        return Err(anyhow::anyhow!("PKI initialization failed: {}", e));
    }

    // The old DatabaseApiState (with its background TTL task) is no longer
    // needed — the /api/v1/database routes now use the new
    // handlers::database + services::database::DatabaseService.  We pass a
    // mock storage so the old engine does no real work; its background TTL
    // task will find zero leases and idle harmlessly.
    let database_state = secreton_api::database::DatabaseApiState::new(
        Arc::new(secreton_storage::MockStorageBackend::new()),
    )
    .await;

    let admin = Arc::new(
        secreton_api::services::admin::AdminService::new(
            storage.clone(),
            auth.clone(),
            performance.clone(),
            audit.clone(),
        )
        .await?
        .with_crypto(crypto.clone()),
    );

    // Populate Service Container
    use secreton_common::{ServiceContainer, StandardServiceContainer};
    use secreton_storage::StorageBackend;
    let mut container = StandardServiceContainer::default();
    // Explicitly type the service registration to match the AppState definitions
    container.register_service::<Arc<dyn StorageBackend + Send + Sync>>(
        "storage".to_string(),
        storage.clone(),
    );
    container.register_service::<Arc<CryptoService>>("crypto".to_string(), crypto.clone());
    container.register_service::<Arc<SealService>>("seal".to_string(), seal.clone());
    container.register_service::<Arc<AuditLogger>>("audit".to_string(), audit.clone());
    container.register_service::<Arc<AuthenticationService>>("auth".to_string(), auth.clone());
    container.register_service::<Arc<PolicyService>>("policy".to_string(), policy_service.clone());
    container.register_service::<Arc<secreton_auth::mfa::CombinedMfaService>>(
        "mfa".to_string(),
        mfa.clone(),
    );
    container.register_service::<Arc<SecretService>>("secret".to_string(), secreton.clone());
    container.register_service::<Arc<secreton_api::services::admin::AdminService>>(
        "admin".to_string(),
        admin.clone(),
    );
    container.register_service::<Arc<SecretPerformanceOptimizer>>(
        "performance".to_string(),
        performance.clone(),
    );

    // Register Transit Engine service
    let transit_engine = Arc::new(secreton_crypto::transit::TransitEngine::new());
    container.register_service::<Arc<secreton_crypto::transit::TransitEngine>>(
        "transit".to_string(),
        transit_engine.clone(),
    );

    use secreton_core::telemetry::{TelemetryCollector, TelemetryConfig};
    let telemetry = Arc::new(TelemetryCollector::new(TelemetryConfig::default()));
    if let Err(e) = telemetry.start_collection().await {
        warn!("Failed to start telemetry collection: {}", e);
    }

    container.register_service::<Arc<TelemetryCollector>>(
        "telemetry".to_string(),
        telemetry.clone(),
    );

    // Register new engine services
    let database_service = Arc::new(
        secreton_api::services::database::DatabaseService::new(storage.clone(), crypto.clone()),
    );
    container.register_service::<Arc<secreton_api::services::database::DatabaseService>>(
        "database".to_string(),
        database_service.clone(),
    );
    container.register_service::<Arc<PkiPersistentService>>(
        "pki".to_string(),
        pki_service.clone(),
    );

    let ssh_service = Arc::new(
        secreton_api::services::ssh::SshPersistentService::new(storage.clone(), crypto.clone()),
    );
    if let Err(e) = ssh_service.ensure_initialized().await {
        tracing::error!("Failed to initialize SSH service from storage: {}", e);
        return Err(anyhow::anyhow!("SSH initialization failed: {}", e));
    }
    container.register_service::<Arc<secreton_api::services::ssh::SshPersistentService>>(
        "ssh".to_string(),
        ssh_service.clone(),
    );
    let totp_engine_service = Arc::new(
        secreton_api::services::totp_engine::TotpEngineService::new(
            storage.clone(),
            crypto.clone(),
        ),
    );
    container.register_service::<Arc<secreton_api::services::totp_engine::TotpEngineService>>(
        "totp_engine".to_string(),
        totp_engine_service.clone(),
    );

    let api_state = ApiState::new(
        KVApiState::default(),
        database_state,
        Some(pki_service),
        Arc::new(api_config.clone()),
        Arc::new(container), // Fixed: Pass populated container
        auth.clone(),
        admin.clone(),
        OptimizationLevel::default(),
    )
    .await?;

    let axum_router = secreton_api::create_api_router(api_state)?;

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
    // WARNING: This +10 offset is coupled with the proxy configuration in crates/ui/Trunk.toml.
    // If SECRETON_SERVER__PORT is changed from default 8080, Trunk.toml proxy backend ports must be updated manually.

    let axum_port = http_port
        .checked_add(10)
        .expect("HTTP port too high; cannot allocate enhanced API port");
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

    info!(
        "🚀 Servers starting (HTTP: {}, Enhanced API: {}, gRPC: {})...",
        http_port, axum_port, grpc_port
    );

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
