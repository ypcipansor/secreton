use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub token: String,
    pub user: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub orphan: bool,
    pub batch: bool,
    pub locked: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
