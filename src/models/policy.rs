use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: i64,
    pub role: String,
    pub path: String, // sekarang support glob/wildcard
    pub action: String,
    pub effect: String, // "allow" atau "deny"
    pub entity_alias: Option<String>, // mapping user OIDC/LDAP/AppRole
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroup {
    pub required_approvals: u32,
    pub approved_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub effect: String, // "allow" atau "deny"
    pub action: String, // misal "read", "write"
    pub path: String,   // glob/wildcard path
    pub condition: Option<serde_json::Value>, // ekspresi/logic opsional
    pub control_group: Option<ControlGroup>, // multi-approval
    pub mfa: Option<bool>, // butuh MFA?
} 