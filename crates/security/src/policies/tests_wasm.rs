#[cfg(test)]
mod tests {
    use crate::policies::sentinel::{SentinelPolicy, EnforcementLevel};
    use chrono::Utc;
    use base64::{engine::general_purpose, Engine as _};
    use crate::policies::policy::{evaluate_with_sentinel, PolicyContext};

    // A minimal WASM module that exports "alloc" and "evaluate" and returns 1 (allow).
    const WASM_ALLOW: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x0f, // Type Section (ID 1, Size 15)
          0x03, // Count 3
          0x60, 0x01, 0x7f, 0x01, 0x7f, // (i32)->i32
          0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // (i32, i32)->i32
          0x60, 0x00, 0x00, // ()->()

        0x03, 0x03, // Function Section (ID 3, Size 3)
          0x02, 0x00, 0x01, // Count 2, Types 0, 1

        0x05, 0x03, // Memory Section (ID 5, Size 3)
          0x01, 0x00, 0x01, // Count 1, Limit 0, 1

        0x07, 0x1d, // Export Section (ID 7, Size 29)
          0x03, // Count 3
          0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, // "memory" mem 0
          0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x00, // "alloc" func 0
          0x08, 0x65, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x65, 0x00, 0x01, // "evaluate" func 1

        0x0a, 0x0b, // Code Section (ID 10, Size 11)
          0x02, // Count 2
          0x04, 0x00, 0x41, 0x00, 0x0b, // Func 0 body: const 0
          0x04, 0x00, 0x41, 0x01, 0x0b  // Func 1 body: const 1
    ];

    // A minimal WASM module that returns 0 (deny).
    const WASM_DENY: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x0f, // Type Section (ID 1, Size 15)
          0x03, // Count 3
          0x60, 0x01, 0x7f, 0x01, 0x7f, // (i32)->i32
          0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // (i32, i32)->i32
          0x60, 0x00, 0x00, // ()->()

        0x03, 0x03,
          0x02, 0x00, 0x01,

        0x05, 0x03,
          0x01, 0x00, 0x01,

        0x07, 0x1d,
          0x03,
          0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
          0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x00,
          0x08, 0x65, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x65, 0x00, 0x01,

        0x0a, 0x0b,
          0x02,
          0x04, 0x00, 0x41, 0x00, 0x0b,
          0x04, 0x00, 0x41, 0x00, 0x0b  // Func 1 body: const 0
    ];

    #[tokio::test]
    async fn test_evaluate_wasm_policy_allow() {
        let wasm_base64 = general_purpose::STANDARD.encode(WASM_ALLOW);
        let policy_code = format!("wasm:{}", wasm_base64);

        let policy = SentinelPolicy {
            name: "test-wasm-allow".to_string(),
            enforcement_level: EnforcementLevel::HardMandatory,
            policy_code,
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        let result = evaluate_with_sentinel(
            &[policy],
            "user1",
            "secret/test",
            "read",
            &PolicyContext {},
        ).await;

        assert!(result, "Should allow");
    }

    #[tokio::test]
    async fn test_evaluate_wasm_policy_deny() {
        let wasm_base64 = general_purpose::STANDARD.encode(WASM_DENY);
        let policy_code = format!("wasm:{}", wasm_base64);

        let policy = SentinelPolicy {
            name: "test-wasm-deny".to_string(),
            enforcement_level: EnforcementLevel::HardMandatory,
            policy_code,
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        let result = evaluate_with_sentinel(
            &[policy],
            "user1",
            "secret/test",
            "read",
            &PolicyContext {},
        ).await;

        assert!(!result, "Should deny");
    }
}
