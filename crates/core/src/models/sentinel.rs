use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelPolicy {
    pub id: i64,
    pub namespace: String,
    pub name: String,
    pub version: u32,
    pub policy_type: String, // "egp", "rgp", "wasm", "hcl"
    pub source_code: String,
    pub egp: bool,
    pub rgp: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
