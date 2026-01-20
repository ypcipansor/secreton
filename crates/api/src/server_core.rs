use crate::{legacy_config::Config, services::auth::AuthenticationService as AuthService, telemetry::{TelemetryCollector, TelemetryConfig}};
use secreton_storage::{PostgresBackend, StorageBackend};
// use crate::AppError; // Use standard error
use secreton_errors::{SecretonError as AppError};
use axum::{
    Router,
    body::Body,
    http::Request,
    routing::{get, post},
};
use chrono;
use std::{net::SocketAddr, sync::Arc};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;

/// Application state shared across all routes
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub auth_service: AuthService,
    pub telemetry: Arc<TelemetryCollector>,
}

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        // Initialize logging
        self.init_logging()?;

        // Initialize storage backend
        let storage: Option<Arc<dyn StorageBackend + Send + Sync>> = if self.config.database_url.starts_with("postgres") {
             match PostgresBackend::new(&self.config.database_url).await {
                Ok(s) => Some(Arc::new(s)),
                Err(e) => {
                    tracing::warn!("Failed to connect to Postgres: {}. Falling back to memory auth.", e);
                    None
                }
             }
        } else {
             tracing::info!("Using in-memory storage (database_url does not start with postgres)");
             None
        };

        // Create auth service
        // Initialize crypto service (needed for auth)
        // Assume storage is available (enforced by earlier check logic or we fail here)
        let storage_backend = storage.ok_or_else(|| anyhow::anyhow!("Storage backend initialization failed"))?;

        let crypto = Arc::new(crate::services::crypto::CryptoService::new(storage_backend.clone()).await.map_err(|e| anyhow::anyhow!(e))?);

        // Convert legacy config to new AuthConfig
        let mut auth_config = crate::config::AuthConfig::default();
        if let Some(s) = &self.config.auth.jwt_secret {
            auth_config.jwt.secret = Some(s.clone());
        }

        let auth_service = AuthService::new(storage_backend, crypto, &auth_config).await.map_err(|e| anyhow::anyhow!(e))?;

        // Initialize telemetry
        let telemetry = Arc::new(TelemetryCollector::new(TelemetryConfig::default()));
        // Start collection in background
        if let Err(e) = telemetry.start_collection().await {
            tracing::warn!("Failed to start telemetry collection: {:?}", e);
        }

        // Create application state
        let state = Arc::new(AppState {
            config: self.config.clone(),
            auth_service,
            telemetry,
        });

        // Create the application router
        let app = self.create_router(state).await?;

        // Start the server
        let addr = SocketAddr::from((
            self.config.server.host.parse::<std::net::IpAddr>()?,
            self.config.server.port,
        ));

        info!("Server listening on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    fn init_logging(&self) -> anyhow::Result<()> {
        let filter = tracing_subscriber::filter::EnvFilter::new("info")
            .add_directive(self.config.server.log_level.parse()?)
            .add_directive("tower_http=info".parse()?);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .init();

        Ok(())
    }

    async fn create_router(&self, state: Arc<AppState>) -> anyhow::Result<Router> {
        // CORS configuration
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_credentials(true);

        // Create the router with common middleware
        let app = Router::new()
            // Health check endpoint (public)
            .route("/health", get(|| async { "OK" }))
            // Auth routes (public)
            // .route("/v1/auth/login", post(crate::handlers::auth::login)) // Assuming handlers will be refactored
            // .route("/v1/auth/refresh", post(crate::handlers::auth::refresh_token))
            // Protected routes
            // .route("/v1/auth/logout", post(crate::handlers::auth::logout))
            // .route("/v1/auth/me", get(crate::handlers::auth::me))
            // .route(
            //     "/v1/auth/change-password",
            //     post(crate::handlers::auth::change_password),
            // )
            // .route("/v1/auth/register", post(crate::handlers::auth::register_user))
            // .route("/v1/auth/users", get(crate::handlers::auth::list_users))
            // Add more protected routes here
            // Apply auth middleware to protected routes
            // .layer(middleware::from_fn_with_state(
            //     state.clone(),
            //     |state: axum::extract::State<Arc<AppState>>,
            //      request: axum::extract::Request,
            //      next: axum::middleware::Next| async move {
            //         auth_middleware(state, request, next).await
            //     },
            // ))
            // Add state and common middleware
            .with_state(state)
            .layer(TraceLayer::new_for_http())
            .layer(cors);

        Ok(app)
    }
}

// Helper function to extract the request body as a string
pub async fn extract_body_string(req: Request<Body>) -> Result<String, AppError> {
    let bytes = axum::body::to_bytes(req.into_body(), usize::MAX).await
        .map_err(|e| AppError::Internal { message: e.to_string() })?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}
