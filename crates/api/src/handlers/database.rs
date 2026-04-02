//! Database Secret Engine Handlers

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
};
use serde_json::Value;

use crate::extractors::AuthenticatedUser;
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
    AuthenticatedUser(user): AuthenticatedUser,
    Json(payload): Json<DatabaseConfig>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    // Only admin/root users may configure database connections
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to configure database engine".to_string(),
        ));
    }

    state.database.set_config(payload).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "Database configuration updated"
    }))))
}

async fn list_roles(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let roles = state.database.list_roles().await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "roles": roles
    }))))
}

async fn add_role(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(payload): Json<DatabaseRole>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    // Only admin/root users may manage roles
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to manage database roles".to_string(),
        ));
    }

    state.database.add_role(&name, payload).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": format!("Role {} created/updated", name)
    }))))
}

async fn generate_credentials(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(role): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let creds = state.database.generate_credentials(&role).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    let value = serde_json::to_value(creds)
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(value)))
}

async fn list_leases(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Vec<Value>>>> {
    let leases = state.database.list_leases().await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(leases)))
}

async fn revoke_lease(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    // Only admin/root users may revoke leases
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to revoke leases".to_string(),
        ));
    }

    state.database.revoke_lease(&id).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "Lease revoked"
    }))))
}
