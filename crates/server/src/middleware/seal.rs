//! Seal gate.
//!
//! While sealed, the barrier key is not in memory and no secret can be decrypted. Rather
//! than let handlers fail one by one with confusing decryption errors, this layer refuses
//! the request with 503 up front.
//!
//! Like [`super::auth`], it carries no path allowlist: the routes that must work while
//! sealed — `sys/init`, `sys/unseal`, `sys/seal-status`, health — are mounted outside this
//! layer in [`crate::router::build_router`]. The previous version matched a list of exact
//! strings inside the middleware, which had to be kept in sync by hand with the router.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use secreton_domain::SecretonError;
use secreton_engines::Services;

use crate::error::ApiError;

pub async fn reject_when_sealed(
    State(services): State<Services>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if services.seal.is_sealed().await {
        return Err(ApiError(SecretonError::ServiceUnavailable {
            service: "secreton is sealed; unseal it at POST /api/v1/sys/unseal".to_string(),
        }));
    }
    Ok(next.run(request).await)
}
