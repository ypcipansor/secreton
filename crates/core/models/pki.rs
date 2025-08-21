use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiCa {
    pub id: i64,
    pub namespace: String,
    pub common_name: String,
    pub pem: String,
    pub private_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiCert {
    pub id: i64,
    pub namespace: String,
    pub common_name: String,
    pub pem: String,
    pub private_key: String,
    pub ca_id: i64,
    pub serial: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
} 