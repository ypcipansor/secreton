//! UI Pages
//!
//! Web interface pages for Secreton

#[cfg(feature = "client")]
pub mod admin;
#[cfg(feature = "client")]
pub mod audit;
#[cfg(feature = "client")]
pub mod dashboard;
#[cfg(feature = "client")]
pub mod login;
#[cfg(feature = "client")]
pub mod secrets;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Page metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageMeta {
    pub title: String,
    pub description: String,
    pub breadcrumbs: Vec<Breadcrumb>,
    pub requires_auth: bool,
    pub required_permissions: Vec<String>,
}

/// Breadcrumb navigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breadcrumb {
    pub title: String,
    pub url: String,
    pub active: bool,
}

/// Page response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageResponse {
    pub meta: PageMeta,
    pub content: String,
    pub data: HashMap<String, serde_json::Value>,
}

impl PageResponse {
    pub fn new(meta: PageMeta, content: String) -> Self {
        Self {
            meta,
            content,
            data: HashMap::new(),
        }
    }

    pub fn with_data(mut self, key: String, value: serde_json::Value) -> Self {
        self.data.insert(key, value);
        self
    }
}

/// Common page utilities
pub struct PageUtils;

impl PageUtils {
    pub fn create_breadcrumbs(path: &str) -> Vec<Breadcrumb> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let mut breadcrumbs = Vec::new();
        let mut current_path = String::new();

        for (i, part) in parts.iter().enumerate() {
            current_path.push('/');
            current_path.push_str(part);

            breadcrumbs.push(Breadcrumb {
                title: Self::format_title(part),
                url: current_path.clone(),
                active: i == parts.len() - 1,
            });
        }

        breadcrumbs
    }

    fn format_title(part: &str) -> String {
        match part {
            "admin" => "Administration".to_string(),
            "audit" => "Audit Logs".to_string(),
            "secrets" => "Secrets".to_string(),
            "login" => "Login".to_string(),
            "dashboard" => "Dashboard".to_string(),
            _ => part
                .chars()
                .enumerate()
                .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c })
                .collect(),
        }
    }

    pub fn default_page_meta(title: &str, path: &str) -> PageMeta {
        PageMeta {
            title: title.to_string(),
            description: format!("{} page for Secreton vault", title),
            breadcrumbs: Self::create_breadcrumbs(path),
            requires_auth: true,
            required_permissions: vec!["read".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breadcrumb_creation() {
        let breadcrumbs = PageUtils::create_breadcrumbs("/admin/secrets");
        assert_eq!(breadcrumbs.len(), 2);
        assert_eq!(breadcrumbs[0].title, "Administration");
        assert_eq!(breadcrumbs[1].title, "Secrets");
        assert!(breadcrumbs[1].active);
    }

    #[test]
    fn test_page_response() {
        let meta = PageUtils::default_page_meta("Test", "/test");
        let response = PageResponse::new(meta, "test content".to_string()).with_data(
            "key".to_string(),
            serde_json::Value::String("value".to_string()),
        );

        assert_eq!(response.content, "test content");
        assert_eq!(response.data.len(), 1);
    }
}
