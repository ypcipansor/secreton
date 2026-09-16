//! Axum extractors.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use secreton_auth::User;
use secreton_domain::SecretonError;

use crate::error::ApiError;
use crate::middleware::auth::CurrentUser;

/// The authenticated principal for the current request.
///
/// The auth middleware has already validated the credential and inserted the user, so this
/// only reads the extension. The previous version re-validated the bearer token here as a
/// fallback, because two different middleware stacks were in play and neither was
/// guaranteed to have run — a second signature check on every extraction, and a silent
/// bypass if the extension was missing for any other reason. With one router there is one
/// stack, so a missing extension means the route was mounted outside it, which is a
/// wiring bug and is reported as one.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub User);

impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CurrentUser>()
            .map(|u| AuthenticatedUser(u.0.clone()))
            .ok_or(ApiError(SecretonError::MissingAuthHeader))
    }
}

impl std::ops::Deref for AuthenticatedUser {
    type Target = User;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
