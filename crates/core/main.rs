mod api;
mod auth;
mod config;
mod error;
mod policy;
mod secrets;
mod server;
mod storage;

use std::{path::Path, sync::Arc};

use anyhow::Context;
use tracing::{error, info};

use crate::{
    api::{create_router, AppState},
    auth::AuthService,
    config::Config,
    policy::PolicyEngine,
    secrets::SecretsService,
    server::Server,
    storage::{Database, MfaStorage, UserStorage},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = Config::from_env().unwrap_or_else(|_| {
        info!("Using default configuration");
        Config::default()
    });

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(match config.server.log_level.as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::ERROR,
        })
        .init();

    // Ensure data directory exists
    std::fs::create_dir_all(&config.server.data_dir)
        .context("Failed to create data directory")?;

    // Initialize database
    let db_path = Path::new(&config.server.data_dir).join("vault.db");
    let db = Database::new(&db_path.to_string_lossy())
        .await
        .context("Failed to initialize database")?;

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&db.pool)
        .await
        .context("Failed to run database migrations")?;

    // Initialize services
    let user_storage = UserStorage::new(db.pool.clone());
    let mfa_storage = MfaStorage::new(db.pool.clone());
    
    let auth_service = AuthService::new(
        user_storage,
        mfa_storage,
        config.auth.clone(),
    );

    let secrets_service = SecretsService::new(
        db.pool.clone(),
        config.secrets.clone(),
    );

    let policy_engine = PolicyEngine::new(db.pool.clone());

    // Create application state
    let state = AppState::new(
        config.clone(),
        auth_service,
        secrets_service,
        policy_engine,
    );

    // Create API router
    let app = create_router(state);

    // Start server
    let server = Server::new(config.server.clone(), app);
    
    info!("Starting server on {}:{}", config.server.host, config.server.port);
    server.run().await?;

    Ok(())
}
