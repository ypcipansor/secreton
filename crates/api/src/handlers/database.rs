//! Database Secret Engine Handlers

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
};
use serde_json::Value;

use crate::extractors::AuthenticatedUser;
use crate::handlers::{AppState, validate_name};
use crate::services::database::DatabaseServiceError;
use crate::{ApiResponse, ApiResult};
use secreton_secrets_database::{DatabaseConfig, DatabaseRole};

/// Validate a system-generated lease ID.
///
/// Lease IDs are produced by [`DatabaseService::generate_credentials`] in the
/// format `db_{role_name}_{uuid}`.  Because the role name can be up to 128
/// characters (the `validate_name` limit) and the UUID suffix is 32 hex chars,
/// the total can reach 164 characters — exceeding `validate_name`'s 128-char
/// cap.  This dedicated validator uses the same character allowlist but raises
/// the length ceiling so that every generated lease ID remains revocable.
fn validate_lease_id(id: &str) -> Result<(), crate::ApiError> {
    if id.is_empty() {
        return Err(crate::ApiError::BadRequest(
            "Lease ID must not be empty".to_string(),
        ));
    }
    // 128 (max role name) + 3 ("db_") + 1 ("_") + 32 (UUID simple) = 164
    if id.len() > 200 {
        return Err(crate::ApiError::BadRequest(
            "Lease ID must not exceed 200 characters".to_string(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(crate::ApiError::BadRequest(
            "Lease ID contains invalid characters".to_string(),
        ));
    }
    if id.contains("..") {
        return Err(crate::ApiError::BadRequest(
            "Lease ID must not contain '..'".to_string(),
        ));
    }
    Ok(())
}

/// Map a [`DatabaseServiceError`] to the appropriate [`crate::ApiError`] variant
/// so that the HTTP response carries the correct status code.
fn map_db_err(err: DatabaseServiceError) -> crate::ApiError {
    match err {
        DatabaseServiceError::NotFound(msg) => crate::ApiError::NotFound(msg),
        DatabaseServiceError::Unavailable(msg) => {
            // SecretonError::ServiceUnavailable maps to 503 in IntoResponse
            crate::ApiError(secreton_errors::SecretonError::ServiceUnavailable { service: msg })
        }
        DatabaseServiceError::BadRequest(msg) => crate::ApiError::BadRequest(msg),
        DatabaseServiceError::Internal(msg) => crate::ApiError::Internal(msg),
    }
}

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
        .map_err(map_db_err)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "Database configuration updated"
    }))))
}

async fn list_roles(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let roles = state.database.list_roles().await
        .map_err(map_db_err)?;

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

    validate_name(&name)?;

    state.database.add_role(&name, payload).await
        .map_err(map_db_err)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": format!("Role {} created/updated", name)
    }))))
}

async fn generate_credentials(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(role): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    // Credential generation creates real users on the target database.
    // Restrict to admin/root users until policy-based authorization is
    // implemented.
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to generate database credentials".to_string(),
        ));
    }

    validate_name(&role)?;

    let creds = state.database.generate_credentials(&role).await
        .map_err(map_db_err)?;

    let value = serde_json::to_value(creds)
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(value)))
}

async fn list_leases(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Vec<Value>>>> {
    // Only admin/root users may list leases (they contain database usernames)
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to list leases".to_string(),
        ));
    }

    let leases = state.database.list_leases().await
        .map_err(map_db_err)?;

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

    validate_lease_id(&id)?;

    state.database.revoke_lease(&id).await
        .map_err(map_db_err)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "Lease revoked"
    }))))
}
