use crate::{
    config::Config,
    error::AppError,
    auth::{self, AuthService, auth_middleware},
};
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, Level};

/// Application state shared across all routes
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
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

        // Create the auth service
        let auth_service = AuthService::new(
            &self.config.auth.jwt_secret,
            &self.config.auth.refresh_secret,
            self.config.auth.token_ttl,
            self.config.auth.refresh_token_ttl,
        );

        // Create application state
        let state = Arc::new(AppState {
            config: self.config.clone(),
            auth_service,
        });

        // Create the application router
        let app = self.create_router(state).await?;

        // Start the server
        let addr = SocketAddr::from((
            self.config.server.host.parse()?,
            self.config.server.port,
        ));

        info!("Server listening on http://{}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await?;

        Ok(())
    }

    fn init_logging(&self) -> anyhow::Result<()> {
        let filter = tracing_subscriber::filter::EnvFilter::new()
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
            .route("/v1/auth/login", post(auth::login))
            .route("/v1/auth/refresh", post(auth::refresh_token))
            
            // Protected routes
            .route("/v1/auth/logout", post(auth::logout))
            // Add more protected routes here
            
            // Apply auth middleware to protected routes
            .layer(middleware::from_fn_with_state(
                state.clone(),
                |state: axum::extract::State<Arc<AppState>>,
                 request: axum::extract::Request,
                 next: axum::middleware::Next| async move {
                    auth_middleware(state, request, next).await
                },
            ))
            
            // Add state and common middleware
            .with_state(state)
            .layer(TraceLayer::new_for_http())
            .layer(cors);

        Ok(app)
    }

    // Helper function to create a response
    fn json_response<T: serde::Serialize>(
        &self,
        status: StatusCode,
        data: T,
    ) -> Result<Response<Body>, AppError> {
        let body = serde_json::to_string(&data)?;
        Ok(Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(body))?)
    }
}

// Helper function to extract the request body as a string
pub async fn extract_body_string(req: Request<Body>) -> Result<String, AppError> {
    let bytes = hyper::body::to_bytes(req.into_body()).await?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}
