use crate::{AppError, auth::auth_impl::AuthService, utils::config::Config, storage::{PostgresStorage, StorageBackend}};
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
    pub external_audit_devices:
        std::sync::Arc<Vec<Box<dyn crate::services::audit::ExternalAuditDevice>>>,
    pub auth_service: AuthService,
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
             match PostgresStorage::from_url(&self.config.database_url).await {
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
        let token_config = secreton_auth::TokenConfig {
            jwt_secret: self.config.auth.jwt_secret.clone(),
            jwt_refresh_secret: self.config.auth.refresh_secret.clone(),
            access_token_duration: chrono::Duration::hours(1),
            refresh_token_duration: chrono::Duration::days(7),
            issuer: "secreton".to_string(),
            audience: "secreton-api".to_string(),
        };
        let jwt_token_service = secreton_auth::JwtTokenService::new(token_config.clone());
        let auth_service = AuthService::new(jwt_token_service, token_config, storage);

        // Create application state
        let state = Arc::new(AppState {
            config: self.config.clone(),
            external_audit_devices: std::sync::Arc::new(vec![]),
            auth_service,
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
            .route("/v1/auth/login", post(crate::auth::login))
            .route("/v1/auth/refresh", post(crate::auth::refresh_token))
            // Protected routes
            .route("/v1/auth/logout", post(crate::auth::logout))
            .route("/v1/auth/me", get(crate::auth::me))
            .route(
                "/v1/auth/change-password",
                post(crate::auth::change_password),
            )
            .route("/v1/auth/register", post(crate::auth::register_user))
            .route("/v1/auth/users", get(crate::auth::list_users))
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
    let bytes = axum::body::to_bytes(req.into_body(), usize::MAX).await?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}
