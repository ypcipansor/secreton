#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::crypto_policy_engine::*;
use secreton_core::services::rbac::*;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Test policy engine operations
    if data.len() < 100 {
        return;
    }

    // Split data for different policy components
    let policy_end = data.len() / 4;
    let context_end = 2 * data.len() / 4;
    let rules_end = 3 * data.len() / 4;

    let policy_data = &data[..policy_end];
    let context_data = &data[policy_end..context_end];
    let rules_data = &data[context_end..rules_end];
    let permissions = &data[rules_end..];

    // Test crypto policy evaluation
    if let Ok(policy_str) = std::str::from_utf8(policy_data) {
        if let Ok(policy) = serde_json::from_str::<CryptoPolicy>(policy_str) {
            let _ = evaluate_crypto_policy(&policy);
            let _ = validate_policy_compliance(&policy);
        }
    }

    // Test RBAC policy evaluation
    if let Ok(context_str) = std::str::from_utf8(context_data) {
        if let Ok(context) = serde_json::from_str::<SecurityContext>(context_str) {
            let _ = evaluate_access_control(&context);
            let _ = check_role_permissions(&context);
        }
    }

    // Test policy rules parsing
    if let Ok(rules_str) = std::str::from_utf8(rules_data) {
        let _ = parse_policy_rules(rules_str);
        let _ = validate_policy_syntax(rules_str);
        let _ = compile_policy_rules(rules_str);
    }

    // Test permission evaluation
    if let Ok(perm_str) = std::str::from_utf8(permissions) {
        if let Ok(perm_map) = serde_json::from_str::<HashMap<String, Vec<String>>>(perm_str) {
            let _ = evaluate_permissions(&perm_map);
            let _ = validate_permission_hierarchy(&perm_map);
        }
    }
});
