use serde::Serialize;
use tabled::{Table, Tabled};

pub trait OutputFormat {
    fn format_json(&self) -> String
    where
        Self: Serialize,
    {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    fn format_table(&self) -> String
    where
        Self: Tabled,
    {
        Table::new([self]).to_string()
    }
}

#[derive(Debug, Serialize, Tabled)]
pub struct SecretInfo {
    pub key: String,
    pub created_at: String,
    pub updated_at: String,
}

impl OutputFormat for SecretInfo {}

#[derive(Debug, Serialize, Tabled)]
pub struct PolicyInfo {
    pub name: String,
    pub version: String,
    pub created_at: String,
    pub updated_at: String,
}

impl OutputFormat for PolicyInfo {}

pub fn success(message: &str) {
    println!("✅ {}", message);
}

pub fn error(message: &str) {
    eprintln!("❌ {}", message);
}

pub fn warning(message: &str) {
    println!("⚠️  {}", message);
}

pub fn info(message: &str) {
    println!("ℹ️  {}", message);
}
