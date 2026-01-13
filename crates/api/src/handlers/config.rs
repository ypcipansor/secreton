use crate::services::config::ConfigService;
use crate::config::ApiConfig;
use secreton_storage::StorageBackend;
use crate::services::auth::AuthenticationService;
use crate::services::audit::{AuditLogger, SecurityEventType};
use warp::{Rejection, Reply};
use std::sync::Arc;
use tracing::{info, error, warn};

/// Handler for saving configuration
pub async fn handle_post_config(
    token: Option<String>,
    config: ApiConfig,
    storage: Arc<dyn StorageBackend>,
    auth: Arc<AuthenticationService>,
    audit: Arc<AuditLogger>,
) -> Result<impl Reply, Rejection> {

    let mut username = "system".to_string();

    // Validate token and check permissions
    let token_str = token.unwrap_or_default();
    match auth.validate_token(&token_str).await {
        Ok(user) => {
            // Check if user has admin permissions
            let is_admin = user.roles.iter().any(|r| r == "admin" || r == "root") || user.is_superuser;
            if !is_admin {
                warn!("Unauthorized config update attempt by user: {}", user.username);
                return Err(warp::reject::custom(crate::ApiError::Authorization("Insufficient permissions".to_string())));
            }
            username = user.username.clone();
            info!("Authorized config update by user: {}", username);
        },
        Err(_) => {
            // Allow if bootstrapping (no users exist yet)
            // This allows the first configuration to be pushed which might set up auth
            let user_count = auth.get_user_count().await.unwrap_or(0);
            if user_count == 0 {
                info!("Allowing config update during bootstrapping (no users found)");
                username = "bootstrapper".to_string();
            } else {
                 warn!("Unauthorized config update attempt: invalid token");
                 return Err(warp::reject::custom(crate::ApiError::Authentication("Invalid token".to_string())));
            }
        }
    }

    info!("Received configuration update request");

    match ConfigService::save_config(storage.as_ref(), &config).await {
        Ok(_) => {
            info!("Configuration updated successfully");

            // Log audit event
            let _ = audit.log_event(SecurityEventType::ConfigChange {
                user: username,
                changed_keys: vec!["all".to_string()], // We don't diff yet
            }).await;

            Ok(warp::reply::json(&crate::ApiResponse::<()>::success(())))
        }
        Err(e) => {
            error!("Failed to update configuration: {}", e);
            Ok(warp::reply::json(&crate::ApiResponse::<()>::error(format!(
                "Failed to update configuration: {}",
                e
            ))))
        }
    }
}

/// Handler for deleting configuration
pub async fn handle_delete_config(
    token: Option<String>,
    storage: Arc<dyn StorageBackend>,
    auth: Arc<AuthenticationService>,
    audit: Arc<AuditLogger>,
) -> Result<impl Reply, Rejection> {
    let username: String;

    // Validate token and check permissions
    let token_str = token.unwrap_or_default();
    match auth.validate_token(&token_str).await {
        Ok(user) => {
            // Check if user has admin permissions
            let is_admin = user.roles.iter().any(|r| r == "admin" || r == "root") || user.is_superuser;
            if !is_admin {
                warn!("Unauthorized config delete attempt by user: {}", user.username);
                return Err(warp::reject::custom(crate::ApiError::Authorization("Insufficient permissions".to_string())));
            }
            username = user.username.clone();
            info!("Authorized config delete by user: {}", username);
        },
        Err(_) => {
             warn!("Unauthorized config delete attempt: invalid token");
             return Err(warp::reject::custom(crate::ApiError::Authentication("Invalid token".to_string())));
        }
    }

    info!("Received configuration delete request");

    match ConfigService::delete_config(storage.as_ref()).await {
        Ok(_) => {
            info!("Configuration deleted successfully");

            // Log audit event
            let _ = audit.log_event(SecurityEventType::ConfigChange {
                user: username,
                changed_keys: vec!["deleted".to_string()],
            }).await;

            Ok(warp::reply::json(&crate::ApiResponse::<()>::success(())))
        }
        Err(e) => {
            error!("Failed to delete configuration: {}", e);
            Ok(warp::reply::json(&crate::ApiResponse::<()>::error(format!(
                "Failed to delete configuration: {}",
                e
            ))))
        }
    }
}

/// Handler for getting configuration
pub async fn handle_get_config(
    storage: Arc<dyn StorageBackend>,
) -> Result<impl Reply, Rejection> {
    info!("Received get configuration request");

    match ConfigService::load_config(storage.as_ref()).await {
        Ok(config) => {
            Ok(warp::reply::json(&crate::ApiResponse::success(config)))
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            Ok(warp::reply::json(&crate::ApiResponse::<()>::error(format!(
                "Failed to load configuration: {}",
                e
            ))))
        }
    }
}
