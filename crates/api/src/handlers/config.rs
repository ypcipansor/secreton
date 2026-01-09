use crate::services::config::ConfigService;
use crate::config::ApiConfig;
use secreton_storage::StorageBackend;
use warp::{Rejection, Reply};
use std::sync::Arc;
use tracing::{info, error};

/// Handler for saving configuration
pub async fn handle_post_config(
    config: ApiConfig,
    storage: Arc<dyn StorageBackend>,
) -> Result<impl Reply, Rejection> {
    info!("Received configuration update request");

    match ConfigService::save_config(storage.as_ref(), &config).await {
        Ok(_) => {
            info!("Configuration updated successfully");
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
