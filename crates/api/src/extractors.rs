use crate::auth::extract_bearer_token;
use crate::handlers::AppState;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use secreton_auth::User;
use std::future::Future;

/// Authenticated user extractor.
///
/// First checks whether the `auth_middleware` (used by `create_api_router`)
/// already validated the token and inserted a [`User`] into request
/// extensions.  If so, the user is returned without a second token
/// validation round-trip.  Falls back to extracting and validating the
/// Bearer token directly so that routes mounted via `create_router` (which
/// uses a different middleware stack) still work.
pub struct AuthenticatedUser(pub User);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        // Try to read a User already inserted by auth_middleware to avoid
        // a redundant token validation.
        let existing_user = parts.extensions.get::<User>().cloned();
        let auth_header = parts.headers.get("authorization").cloned();
        let state = state.clone();

        async move {
            // Fast path: user already validated by upstream middleware.
            if let Some(user) = existing_user {
                return Ok(AuthenticatedUser(user));
            }

            // Slow path: validate the token ourselves.
            let auth_header = auth_header.ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing authorization header".to_string(),
            ))?;

            let token = extract_bearer_token(&auth_header).ok_or((
                StatusCode::UNAUTHORIZED,
                "Invalid authorization header".to_string(),
            ))?;

            state
                .auth
                .validate_token(&token)
                .await
                .map(AuthenticatedUser)
                .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
        }
    }
}
