use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub id: String,
    pub user: String,
    pub resource: String,
    pub resource_type: String, // misal: "db", "aws", "api_key"
    pub issued_at: DateTime<Utc>,
    pub expired_at: DateTime<Utc>,
    pub status: String, // "active", "revoked", "expired"
    pub namespace: String,
}
