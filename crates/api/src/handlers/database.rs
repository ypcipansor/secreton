//! Database Secret Engine Handlers

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
};
use serde_json::Value;

use crate::handlers::AppState;
use crate::{ApiResponse, ApiResult};
use secreton_secrets_database::{DatabaseConfig, DatabaseRole};

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/config", post(set_config))
        .route("/roles", get(list_roles))
        .route("/roles/{name}", post(add_role))
        .route("/creds/{role}", get(generate_credentials))
        .route("/leases", get(list_leases))
        .route("/leases/{id}", delete(revoke_lease))
}

async fn set_config(
    State(state): State<AppState>,
    Json(payload): Json<DatabaseConfig>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    state.database.set_config(payload).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "Database configuration updated"
    }))))
}

async fn list_roles(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let roles = state.database.list_roles().await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "roles": roles
    }))))
}

async fn add_role(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<DatabaseRole>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    state.database.add_role(&name, payload).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": format!("Role {} created/updated", name)
    }))))
}

async fn generate_credentials(
    State(state): State<AppState>,
    Path(role): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let creds = state.database.generate_credentials(&role).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::to_value(creds).unwrap())))
}

async fn list_leases(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<Vec<Value>>>> {
    let leases = state.database.list_leases().await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(leases)))
}

async fn revoke_lease(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    state.database.revoke_lease(&id).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "Lease revoked"
    }))))
}
