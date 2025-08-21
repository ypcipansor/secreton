use askama::Template;
use serde::Serialize;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub title: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub title: String,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub title: String,
    pub user: String,
}

#[derive(Serialize)]
pub struct SecretInfo {
    pub key: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "secrets.html")]
pub struct SecretsTemplate {
    pub title: String,
    pub secrets: Vec<SecretInfo>,
}

#[derive(Serialize)]
pub struct PolicyInfo {
    pub name: String,
    pub version: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "policies.html")]
pub struct PoliciesTemplate {
    pub title: String,
    pub policies: Vec<PolicyInfo>,
}
