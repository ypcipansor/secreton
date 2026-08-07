use crate::error::{ApiError, ApiResult};
use crate::extractors::AuthenticatedUser;
use crate::handlers::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use secreton_domain::ApiResponse;
use secreton_domain::SecretonError;
pub use secreton_domain::dto::lifecycle::{LifecycleStatistics, SecretLifecycle};
use secreton_engines::Services;
use secreton_engines::lifecycle::LifecycleHook;
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/stats", get(get_lifecycle_stats))
        .route("/status/{*path}", get(get_secret_lifecycle_status))
        .route("/extend/{*path}", post(extend_secret_ttl))
        .route("/hooks", get(list_hooks).post(create_hook))
        .route(
            "/hooks/{id}",
            get(get_hook).put(update_hook).delete(delete_hook),
        )
}

async fn get_lifecycle_stats(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<LifecycleStatistics>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError(SecretonError::Authorization {
            message: "Only admins can access statistics".to_string(),
        }));
    }
    let stats = state.lifecycle.manager().get_statistics().await;
    Ok(Json(ApiResponse::success(stats)))
}

async fn get_secret_lifecycle_status(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<SecretLifecycle>>> {
    state.secret.get_secret(&path, &user, None).await?;
    let lifecycle = state
        .lifecycle
        .manager()
        .get_lifecycle(&path)
        .await
        .ok_or_else(|| {
            ApiError(SecretonError::NotFound {
                resource: format!("Lifecycle for {} not found", path),
            })
        })?;
    Ok(Json(ApiResponse::success(lifecycle)))
}

#[derive(Debug, Deserialize)]
pub struct ExtendTtlRequest {
    pub additional_days: u32,
}

async fn extend_secret_ttl(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Json(payload): Json<ExtendTtlRequest>,
) -> ApiResult<Json<ApiResponse<SecretLifecycle>>> {
    let secret = state.secret.get_secret(&path, &user, None).await?;
    let current_expires = secret.expires_at.unwrap_or_else(chrono::Utc::now);
    let new_expires = current_expires + chrono::Duration::days(payload.additional_days as i64);

    state
        .secret
        .put_secret_internal(
            &path,
            secret.data,
            Some(secret.metadata),
            &user,
            None,
            Some(Some(new_expires)),
        )
        .await?;

    let lifecycle = state
        .lifecycle
        .manager()
        .get_lifecycle(&path)
        .await
        .ok_or_else(|| {
            ApiError(SecretonError::Internal {
                message: "Failed to retrieve updated lifecycle".to_string(),
            })
        })?;
    Ok(Json(ApiResponse::success(lifecycle)))
}

async fn list_hooks(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Vec<LifecycleHook>>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError(SecretonError::Authorization {
            message: "Only admins can manage hooks".to_string(),
        }));
    }
    let hooks = state.lifecycle.list_hooks().await.map_err(|e| {
        ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;
    Ok(Json(ApiResponse::success(hooks)))
}

async fn get_hook(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
) -> ApiResult<Json<ApiResponse<LifecycleHook>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError(SecretonError::Authorization {
            message: "Only admins can manage hooks".to_string(),
        }));
    }
    let hook = state
        .lifecycle
        .get_hook(&id)
        .await
        .map_err(|e| {
            ApiError(SecretonError::Internal {
                message: e.to_string(),
            })
        })?
        .ok_or_else(|| {
            ApiError(SecretonError::NotFound {
                resource: format!("Hook {} not found", id),
            })
        })?;
    Ok(Json(ApiResponse::success(hook)))
}

async fn create_hook(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(hook): Json<LifecycleHook>,
) -> ApiResult<Json<ApiResponse<()>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError(SecretonError::Authorization {
            message: "Only admins can manage hooks".to_string(),
        }));
    }
    state.lifecycle.create_hook(hook).await.map_err(|e| {
        ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;
    Ok(Json(ApiResponse::success(())))
}

async fn update_hook(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
    Json(mut hook): Json<LifecycleHook>,
) -> ApiResult<Json<ApiResponse<()>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError(SecretonError::Authorization {
            message: "Only admins can manage hooks".to_string(),
        }));
    }
    hook.hook_id = id;
    state.lifecycle.update_hook(hook).await.map_err(|e| {
        ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;
    Ok(Json(ApiResponse::success(())))
}

async fn delete_hook(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError(SecretonError::Authorization {
            message: "Only admins can manage hooks".to_string(),
        }));
    }
    state.lifecycle.delete_hook(&id).await.map_err(|e| {
        ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;
    Ok(Json(ApiResponse::success(())))
}
