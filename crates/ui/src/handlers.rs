use axum::{
    extract::Path,
    http::StatusCode,
    response::{Html, Response},
    Form,
};
use serde::Deserialize;
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

pub async fn login(Form(form): Form<LoginForm>) -> Result<Html<String>, StatusCode> {
    // TODO: Implement authentication logic
    if form.username == "admin" && form.password == "admin" {
        // Redirect to dashboard on success
        let template = DashboardTemplate {
            title: "Dashboard - Brankas".to_string(),
            user: form.username,
        };
        Ok(Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string())))
    } else {
        let template = LoginTemplate {
            title: "Login - Brankas".to_string(),
            error: Some("Invalid credentials".to_string()),
        };
        Ok(Html(askama::Template::render(&template).unwrap_or_else(|_| "Error rendering template".to_string())))
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
    use crate::assets::Assets;
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
