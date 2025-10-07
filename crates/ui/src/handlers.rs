use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Response},
    Form,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::auth::{AuthService, AuthError};
use crate::templates::*;

pub async fn index() -> Html<String> {
    let template = IndexTemplate {
        title: "Brankas Security System".to_string(),
    };
    Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string()))
}

pub async fn login_page() -> Html<String> {
    let template = LoginTemplate {
        title: "Login - Brankas".to_string(),
        error: None,
    };
    Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string()))
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

/// SECURE LOGIN IMPLEMENTATION
/// Uses Argon2id, constant-time comparison, rate limiting, and session management
pub async fn login(
    State(auth): State<Arc<AuthService>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Html<String>, StatusCode> {
    // Extract IP address and user agent for security logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    // Attempt login with proper authentication
    match auth.login(&form.username, &form.password, ip_address, user_agent).await {
        Ok(session) => {
            // Successful login - redirect to dashboard
            // In production, set secure HTTP-only session cookie here
            let template = DashboardTemplate {
                title: "Dashboard - Brankas".to_string(),
                user: form.username,
            };
            Ok(Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string())))
        }
        Err(AuthError::InvalidCredentials) => {
            let template = LoginTemplate {
                title: "Login - Brankas".to_string(),
                error: Some("Invalid username or password".to_string()),
            };
            Ok(Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string())))
        }
        Err(AuthError::AccountLocked) => {
            let template = LoginTemplate {
                title: "Login - Brankas".to_string(),
                error: Some("Account is locked due to too many failed login attempts. Please try again later.".to_string()),
            };
            Ok(Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string())))
        }
        Err(AuthError::RateLimitExceeded) => {
            let template = LoginTemplate {
                title: "Login - Brankas".to_string(),
                error: Some("Too many login attempts. Please try again in 15 minutes.".to_string()),
            };
            Ok(Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string())))
        }
        Err(e) => {
            let template = LoginTemplate {
                title: "Login - Brankas".to_string(),
                error: Some(format!("Authentication error: {}", e)),
            };
            Ok(Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string())))
        }
    }
}

pub async fn dashboard() -> Html<String> {
    let template = DashboardTemplate {
        title: "Dashboard - Brankas".to_string(),
        user: "Current User".to_string(),
    };
    Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string()))
}

pub async fn secrets_page() -> Html<String> {
    let template = SecretsTemplate {
        title: "Secrets - Brankas".to_string(),
        secrets: vec![],
    };
    Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string()))
}

pub async fn policies_page() -> Html<String> {
    let template = PoliciesTemplate {
        title: "Policies - Brankas".to_string(),
        policies: vec![],
    };
    Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string()))
}

pub async fn serve_static(Path(file): Path<String>) -> Result<Response<Vec<u8>>, StatusCode> {
    // TODO: Re-enable when assets module is fixed
// use crate::assets::Assets;
    use rust_embed::RustEmbed;

    let file = file.trim_start_matches('/');
    if let Some(content) = Assets::get(file) {
        let mime_type = mime_guess::from_path(file).first_or_octet_stream();
        
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", mime_type.as_ref())
            .body(content.data.to_vec())
            .unwrap())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
