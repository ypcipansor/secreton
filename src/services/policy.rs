use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::models::sentinel::SentinelPolicy;
use crate::services::audit::log_audit_external;
use wasmtime::{Engine, Store, Module, Instance, Func};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub effect: String, // "allow" atau "deny"
    pub action: String, // misal "read", "write"
    pub path: String,   // glob/wildcard path
    pub condition: Option<Value>, // ekspresi/logic opsional
    pub control_group: Option<ControlGroup>, // multi-approval
    pub mfa: Option<bool>, // butuh MFA?
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroup {
    pub required_approvals: u32,
    pub approved_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    pub fn evaluate(&self, user: &str, path: &str, action: &str, context: Option<&Value>) -> bool {
        for rule in &self.rules {
            if rule.action == action && glob::Pattern::new(&rule.path).map(|p| p.matches(path)).unwrap_or(false) {
                // Evaluasi control group
                if let Some(cg) = &rule.control_group {
                    if cg.approved_by.len() < cg.required_approvals as usize {
                        // Belum cukup approval
                        return false;
                    }
                }
                // Evaluasi MFA
                if rule.mfa == Some(true) {
                    if let Some(ctx) = context {
                        if !ctx.get("mfa_passed").and_then(|v| v.as_bool()).unwrap_or(false) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if rule.effect == "deny" {
                    return false;
                }
                if rule.effect == "allow" {
                    return true;
                }
            }
        }
        false // default deny
    }
}

pub async fn evaluate_with_sentinel(
    sentinel_policies: &[SentinelPolicy],
    user: &str,
    path: &str,
    action: &str,
    context: Option<&serde_json::Value>,
    state: &crate::core::AppState,
) -> bool {
    use std::collections::HashMap;
    // Group by (namespace, name), ambil versi terbaru
    let mut latest: HashMap<(String, String), &SentinelPolicy> = HashMap::new();
    for pol in sentinel_policies {
        let key = (pol.namespace.clone(), pol.name.clone());
        if let Some(existing) = latest.get(&key) {
            if pol.version > existing.version {
                latest.insert(key, pol);
            }
        } else {
            latest.insert(key, pol);
        }
    }
    // Chaining: urutkan berdasarkan (namespace, name), lalu eksekusi berurutan (deny jika salah satu deny)
    let mut policies: Vec<&SentinelPolicy> = latest.values().cloned().collect();
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    for pol in policies {
        if pol.policy_type == "deny_all" {
            let _ = log_audit_external(&state.external_audit_devices, "sentinel_eval", user, &pol.name, "denied").await;
            return false;
        }
        if pol.policy_type == "egp" || pol.policy_type == "rgp" {
            // Eksekusi WASM jika policy_type wasm
            if pol.policy_type == "wasm" {
                let engine = Engine::default();
                if let Ok(module) = Module::new(&engine, &pol.source_code) {
                    let mut store = Store::new(&engine, ());
                    if let Ok(instance) = Instance::new(&mut store, &module, &[]) {
                        if let Ok(func) = instance.get_func(&mut store, "evaluate") {
                            // Dummy: panggil func tanpa argumen, asumsikan bool return
                            if let Ok(_result) = func.call(&mut store, &[], &mut []) {
                                let allowed = true; // Dummy: asumsikan true jika tidak error
                                let _ = log_audit_external(&state.external_audit_devices, "sentinel_eval", user, &pol.name, if allowed { "allowed" } else { "denied" }).await;
                                if !allowed {
                                    return false;
                                }
                            }
                        }
                    }
                }
            } else {
                // HCL/dummy: jika ada kata "allow" di source_code, allow
                let allowed = pol.source_code.contains("allow");
                let _ = log_audit_external(&state.external_audit_devices, "sentinel_eval", user, &pol.name, if allowed { "allowed" } else { "denied" }).await;
                if !allowed {
                    return false;
                }
            }
        }
    }
    true
}

// Integrasi ke policy engine utama
pub async fn check_policy_with_sentinel(
    sentinel_policies: &[SentinelPolicy],
    user: &str,
    path: &str,
    action: &str,
    context: Option<&serde_json::Value>,
    rbac_roles: &[String],
    rbac_policies: &[crate::models::policy::Policy],
    policyset_json: Option<&str>,
) -> bool {
    if !evaluate_with_sentinel(sentinel_policies, user, path, action, context).await {
        return false;
    }
    // Lanjut evaluasi RBAC/ACL biasa
    crate::services::rbac::check_policy(rbac_roles, rbac_policies, path, action, policyset_json)
}

// Contoh: policy as code (JSON)
// {
//   "rules": [
//     { "effect": "allow", "action": "read", "path": "/secrets/*" },
//     { "effect": "deny", "action": "delete", "path": "/secrets/protected/*" }
//   ]
// }

// TODO: Integrasi Sentinel-style policy (WASM/DSL) di masa depan 

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::models::sentinel::SentinelPolicy;
    use crate::core::AppState;
    use std::sync::Arc;

    fn dummy_state() -> AppState {
        use crate::storage::Storage;
        use crate::utils::config::Config;
        AppState {
            storage: Arc::new(Storage::new_in_memory().unwrap()),
            auth_manager: Arc::new(crate::auth::AuthManager::new("secret", Arc::new(Storage::new_in_memory().unwrap())).unwrap()),
            secret_manager: Arc::new(crate::secrets::SecretManager::new("key").unwrap()),
            config: Config::default(),
            plugin_registry: Arc::new(crate::services::plugin::PluginRegistry::new()),
            node_id: "testnode".to_string(),
            peers: vec![],
            is_active: true,
            cluster_status: Arc::new(std::sync::Mutex::new(crate::core::ClusterStatus::default())),
            replication_mode: "none".to_string(),
            replication_peers: vec![],
            replication_status: Arc::new(std::sync::Mutex::new(crate::core::ReplicationStatus::default())),
            audit_devices: Arc::new(vec![]),
            external_audit_devices: Arc::new(vec![]),
            engine_registry: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    #[tokio::test]
    async fn test_evaluate_with_sentinel_versioning() {
        let state = dummy_state();
        let mut policies = vec![
            SentinelPolicy {
                id: 1,
                namespace: "ns1".to_string(),
                name: "p1".to_string(),
                version: 1,
                policy_type: "egp".to_string(),
                source_code: "deny".to_string(),
                egp: true,
                rgp: false,
                created_at: Utc::now(),
            },
            SentinelPolicy {
                id: 2,
                namespace: "ns1".to_string(),
                name: "p1".to_string(),
                version: 2,
                policy_type: "egp".to_string(),
                source_code: "allow".to_string(),
                egp: true,
                rgp: false,
                created_at: Utc::now(),
            },
            SentinelPolicy {
                id: 3,
                namespace: "ns1".to_string(),
                name: "p2".to_string(),
                version: 1,
                policy_type: "egp".to_string(),
                source_code: "deny".to_string(),
                egp: true,
                rgp: false,
                created_at: Utc::now(),
            },
        ];
        // Hanya versi terbaru p1 (version=2, allow) dan p2 (version=1, deny) yang dieksekusi
        let allowed = evaluate_with_sentinel(&policies, "user", "/foo", "read", None, &state).await;
        assert!(!allowed, "Chaining: salah satu policy deny, maka deny");
        // Jika p2 dihapus, hanya p1 (allow) yang aktif
        policies.retain(|p| p.name != "p2");
        let allowed = evaluate_with_sentinel(&policies, "user", "/foo", "read", None, &state).await;
        assert!(allowed, "Versi terbaru p1 allow, maka allow");
        // Tambah policy_type deny_all
        policies.push(SentinelPolicy {
            id: 4,
            namespace: "ns1".to_string(),
            name: "p3".to_string(),
            version: 1,
            policy_type: "deny_all".to_string(),
            source_code: "".to_string(),
            egp: false,
            rgp: false,
            created_at: Utc::now(),
        });
        let allowed = evaluate_with_sentinel(&policies, "user", "/foo", "read", None, &state).await;
        assert!(!allowed, "Jika ada deny_all, selalu deny");
    }
} 