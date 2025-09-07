use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    // Additional fields required by PKI engine
    pub serial_number: String,
    pub certificate: String,
    pub issuing_ca: String,
    pub ca_chain: Vec<String>,
    pub private_key_type: String,
    pub alt_names: Vec<String>,
    pub ip_sans: Vec<String>,
    pub uri_sans: Vec<String>,
    pub other_sans: Vec<String>,
    pub ou: Vec<String>,
    pub organization: Vec<String>,
    pub country: Vec<String>,
    pub locality: Vec<String>,
    pub province: Vec<String>,
    pub street_address: Vec<String>,
    pub postal_code: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub revocation_time: Option<i64>,
    pub revocation_time_rfc3339: Option<String>,
}
