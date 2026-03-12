use crate::auth::extract_bearer_token;
use crate::handlers::AppState;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use secreton_auth::User;
use std::future::Future;

/// Authenticated user extractor
pub struct AuthenticatedUser(pub User);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let auth_header = parts.headers.get("authorization").cloned();
        let state = state.clone();

        async move {
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
