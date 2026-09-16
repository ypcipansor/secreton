//! Authentication.
//!
//! This layer answers one question — who is calling — and nothing else. It carries no
//! allowlist of public paths. The previous implementation did, and kept a hand-maintained
//! list of fifteen exact strings inside the middleware; adding a public route meant
//! remembering to edit it, and forgetting meant a login endpoint that required a session.
//! Public routes now sit outside this layer in [`crate::router::build_router`], so the
//! routing tree is the allowlist and it cannot drift.
//!
//! Two credential shapes are accepted, resolving to the same [`CurrentUser`]:
//!
//! - a session cookie, for the browser — `httpOnly` so injected script cannot read it
//! - `Authorization: Bearer`, for the CLI, the agent and other services

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::CookieJar;
use secreton_auth::User;
use secreton_domain::SecretonError;
use secreton_domain::session::SESSION_COOKIE;
use secreton_engines::Services;

use crate::error::ApiError;

/// The authenticated principal, inserted as a request extension.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub User);

/// Paths a user with an unfinished MFA enrolment may still reach.
///
/// Matched exactly, never by `contains` or `starts_with`: a secret named `mfa` would
/// satisfy a substring test and let a half-enrolled session read secrets. `mfa/disable`
/// is deliberately absent — a user who has not enrolled has nothing to disable, and
/// allowing it would let them stay half-enrolled indefinitely.
pub const MFA_PENDING_ALLOWED: &[&str] = &[
    "/api/v1/auth/mfa/setup",
    "/api/v1/auth/mfa/verify",
    "/api/v1/auth/logout",
];

pub async fn require_authentication(
    State(services): State<Services>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let path = request.uri().path().to_string();

    let token = extract_credential(&request).ok_or(ApiError(SecretonError::MissingAuthHeader))?;

    let user = services.auth.validate_token(&token).await.map_err(|_| {
        ApiError(SecretonError::TokenInvalid {
            reason: "token rejected".to_string(),
        })
    })?;

    enforce_mfa_pending(&user, &path)?;

    let mut request = request;
    request.extensions_mut().insert(CurrentUser(user.clone()));
    // Kept for handlers that still extract `User` directly.
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Pull the bearer token or session cookie out of a request.
fn extract_credential(request: &Request) -> Option<String> {
    if let Some(bearer) = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        return Some(bearer.to_string());
    }

    let jar = CookieJar::from_headers(request.headers());
    jar.get(SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|v| !v.is_empty())
}

/// Reject a half-enrolled session on any path outside [`MFA_PENDING_ALLOWED`].
pub fn enforce_mfa_pending(user: &User, path: &str) -> Result<(), ApiError> {
    let pending = user
        .metadata
        .get("mfa_pending")
        .map(|v| v == "true")
        .unwrap_or(false);

    if pending && !MFA_PENDING_ALLOWED.contains(&path) {
        return Err(ApiError(SecretonError::MfaRequired));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn user_with_mfa_pending(pending: bool) -> User {
        let mut metadata = HashMap::new();
        if pending {
            metadata.insert("mfa_pending".to_string(), "true".to_string());
        }
        User {
            id: "u1".into(),
            username: "alice".into(),
            metadata,
            ..Default::default()
        }
    }

    #[test]
    fn a_fully_enrolled_user_reaches_every_path() {
        let user = user_with_mfa_pending(false);
        for path in ["/api/v1/secret/kv/app", "/api/v1/admin/users"] {
            assert!(enforce_mfa_pending(&user, path).is_ok());
        }
    }

    #[test]
    fn a_half_enrolled_user_reaches_only_the_enrolment_paths() {
        let user = user_with_mfa_pending(true);
        for path in MFA_PENDING_ALLOWED {
            assert!(enforce_mfa_pending(&user, path).is_ok(), "blocked {path}");
        }
        assert!(enforce_mfa_pending(&user, "/api/v1/secret/kv/app").is_err());
    }

    #[test]
    fn a_secret_named_like_an_mfa_path_does_not_bypass_the_check() {
        let user = user_with_mfa_pending(true);
        // These all contain an allowed path as a substring. Exact matching is what
        // stops them; a `contains` or `starts_with` test would let every one through.
        for path in [
            "/api/v1/secret/api/v1/auth/mfa/setup",
            "/api/v1/auth/mfa/setup/../../secret/kv",
            "/api/v1/auth/mfa/setupX",
            "/api/v1/auth/mfa/verify/extra",
        ] {
            assert!(
                enforce_mfa_pending(&user, path).is_err(),
                "MFA gate bypassed by {path}"
            );
        }
    }

    #[test]
    fn disabling_mfa_is_not_reachable_while_enrolment_is_pending() {
        let user = user_with_mfa_pending(true);
        assert!(enforce_mfa_pending(&user, "/api/v1/auth/mfa/disable").is_err());
    }
}
