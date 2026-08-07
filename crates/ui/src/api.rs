//! Data access from the UI, over Leptos server functions.
//!
//! Every call here runs **on the server**. Under `ssr` the body executes directly against
//! `secreton-engines`; under `hydrate` the `#[server]` macro generates the HTTP call for
//! the browser. Two things follow, and both were problems before:
//!
//! 1. **The browser never holds a token.** The session cookie is `HttpOnly`, so the
//!    request carries it automatically and no script can read it. The old code kept a JWT
//!    in `localStorage` and attached it by hand.
//! 2. **Request and response types are shared.** A mismatch between the UI and the API is
//!    a compile error. The old client parsed responses by trying `ApiResponse<T>` and
//!    falling back to raw `T`, because the warp and Axum halves of the API disagreed on
//!    the envelope.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "ssr")]
use secreton_engines::Services;

/// Health of the system, as shown on the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemStatus {
    pub sealed: bool,
    pub version: String,
    pub storage_backend: String,
    pub secret_count: u64,
}

/// Look up the services from the request-scoped Leptos context.
///
/// `secreton-server` provides them for every server-function call, so a handler that
/// forgets to is a startup failure rather than a silent `None` at request time.
#[cfg(feature = "ssr")]
fn services() -> Result<Services, ServerFnError> {
    use_context::<Services>().ok_or_else(|| {
        ServerFnError::new("services were not provided to the server-function context")
    })
}

#[server(name = GetSystemStatus, prefix = "/api/sfn")]
pub async fn system_status() -> Result<SystemStatus, ServerFnError> {
    let services = services()?;
    Ok(SystemStatus {
        sealed: services.seal.is_sealed().await,
        version: env!("CARGO_PKG_VERSION").to_string(),
        storage_backend: format!("{:?}", services.config.storage.backend_type),
        secret_count: services
            .storage
            .count(&Default::default())
            .await
            .unwrap_or(0),
    })
}

/// Credentials submitted by the login form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
}

/// What the UI needs to know about the signed-in user. Deliberately not the full
/// `User` record: password hashes and MFA secrets must never cross to the browser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionUser {
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub mfa_pending: bool,
}

#[server(name = Login, prefix = "/api/sfn")]
pub async fn login(credentials: Credentials) -> Result<SessionUser, ServerFnError> {
    use secreton_engines::services::auth::ApiLoginRequest;

    let services = services()?;
    let (client_ip, user_agent) = client_metadata();

    let response = services
        .auth
        .login(
            ApiLoginRequest {
                username: credentials.username,
                password: credentials.password,
                mfa_code: credentials.mfa_code.filter(|c| !c.is_empty()),
            },
            client_ip,
            user_agent,
        )
        .await
        // The error is deliberately not forwarded verbatim: distinguishing "no such user"
        // from "wrong password" turns the login form into a username oracle.
        .map_err(|e| {
            tracing::warn!(error = %e, "login failed");
            ServerFnError::new("invalid credentials")
        })?;

    let token = response.token;

    // The cookie is set here, inside the server function, so the token is issued and
    // stored without ever being handed to the page.
    set_session_cookie(
        &token.access_token,
        i64::try_from(token.expires_in).unwrap_or(i64::MAX),
    )?;

    Ok(SessionUser {
        mfa_pending: token
            .user
            .metadata
            .get("mfa_pending")
            .map(|v| v == "true")
            .unwrap_or(false),
        username: token.user.username,
        display_name: token.user.display_name,
        roles: token.user.roles,
    })
}

/// Client address and user agent, recorded on the session for auditing.
#[cfg(feature = "ssr")]
fn client_metadata() -> (String, String) {
    let headers = use_context::<axum::http::HeaderMap>();
    let header = |name: &str| {
        headers
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string()
    };
    (header("x-forwarded-for"), header("user-agent"))
}

#[cfg(not(feature = "ssr"))]
fn client_metadata() -> (String, String) {
    (String::new(), String::new())
}

#[server(name = Logout, prefix = "/api/sfn")]
pub async fn logout() -> Result<(), ServerFnError> {
    let services = services()?;
    if let Some(token) = current_token() {
        // Revoke server-side as well as clearing the cookie. Clearing alone would leave
        // a still-valid token that anyone who captured it could keep using.
        services
            .auth
            .revoke_token(token, chrono::Utc::now() + chrono::Duration::days(1))
            .await;
    }
    clear_session_cookie()?;
    Ok(())
}

#[server(name = CurrentSession, prefix = "/api/sfn")]
pub async fn current_session() -> Result<Option<SessionUser>, ServerFnError> {
    let services = services()?;
    let Some(token) = current_token() else {
        return Ok(None);
    };
    let Ok(user) = services.auth.validate_token(&token).await else {
        return Ok(None);
    };
    Ok(Some(SessionUser {
        mfa_pending: user
            .metadata
            .get("mfa_pending")
            .map(|v| v == "true")
            .unwrap_or(false),
        username: user.username,
        display_name: user.display_name,
        roles: user.roles,
    }))
}

// ---------------------------------------------------------------------------
// Server-only cookie plumbing
// ---------------------------------------------------------------------------

#[cfg(feature = "ssr")]
const SESSION_COOKIE: &str = "secreton_session";

#[cfg(feature = "ssr")]
fn current_token() -> Option<String> {
    let headers = use_context::<axum::http::HeaderMap>()?;
    let cookies = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|c| {
        let (name, value) = c.trim().split_once('=')?;
        (name == SESSION_COOKIE).then(|| value.to_string())
    })
}

#[cfg(not(feature = "ssr"))]
fn current_token() -> Option<String> {
    None
}

#[cfg(feature = "ssr")]
fn set_session_cookie(token: &str, ttl_seconds: i64) -> Result<(), ServerFnError> {
    // `Secure` is asserted whenever the request arrived over TLS. Setting it
    // unconditionally would make login silently fail over plain `http://localhost`,
    // because the browser drops the cookie without an error the page can see.
    let secure = use_context::<axum::http::HeaderMap>()
        .and_then(|h| {
            h.get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("https"))
        })
        .unwrap_or(false);

    let cookie = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={ttl_seconds}{}",
        if secure { "; Secure" } else { "" }
    );
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.insert_header(
            axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&cookie)
                .map_err(|e| ServerFnError::new(format!("invalid session cookie: {e}")))?,
        );
    }
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn set_session_cookie(_token: &str, _ttl_seconds: i64) -> Result<(), ServerFnError> {
    Ok(())
}

#[cfg(feature = "ssr")]
fn clear_session_cookie() -> Result<(), ServerFnError> {
    // Attributes must match the ones used when setting, or the browser treats this as a
    // different cookie and the original session stays live.
    let cookie = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.insert_header(
            axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&cookie)
                .map_err(|e| ServerFnError::new(format!("invalid session cookie: {e}")))?,
        );
    }
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn clear_session_cookie() -> Result<(), ServerFnError> {
    Ok(())
}
