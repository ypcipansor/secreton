use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelPolicy {
    pub id: Option<String>,
    pub namespace: String,
    pub name: String,
    pub version: u32,
    pub policy_type: String,
    pub source_code: String,
    pub egp: Option<bool>,
    pub rgp: Option<bool>,
    pub created_at: DateTime<Utc>,
}
