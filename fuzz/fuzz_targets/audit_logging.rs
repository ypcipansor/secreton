#![no_main]

use chrono::{DateTime, Utc};
use libfuzzer_sys::fuzz_target;
use secreton_core::services::audit::*;

fuzz_target!(|data: &[u8]| {
    // Test audit logging operations
    if data.len() < 100 {
        return;
    }

    // Split data for different audit components
    let event_end = data.len() / 4;
    let user_end = 2 * data.len() / 4;
    let metadata_end = 3 * data.len() / 4;

    let event_data = &data[..event_end];
    let user_data = &data[event_end..user_end];
    let metadata = &data[user_end..metadata_end];
    let log_data = &data[metadata_end..];

    // Test audit event parsing
    if let Ok(event_str) = std::str::from_utf8(event_data) {
        if let Ok(event) = serde_json::from_str::<AuditEvent>(event_str) {
            let _ = validate_audit_event(&event);
            let _ = format_audit_event(&event);
            let _ = extract_event_metadata(&event);
        }
    }

    // Test user context parsing
    if let Ok(user_str) = std::str::from_utf8(user_data) {
        let _ = parse_user_context(user_str);
        let _ = validate_user_identity(user_str);
        let _ = extract_user_metadata(user_str);
    }

    // Test audit metadata parsing
    if let Ok(metadata_str) = std::str::from_utf8(metadata) {
        let _ = parse_audit_metadata(metadata_str);
        let _ = validate_metadata_schema(metadata_str);
    }

    // Test log entry parsing and validation
    if let Ok(log_str) = std::str::from_utf8(log_data) {
        let _ = parse_log_entry(log_str);
        let _ = validate_log_format(log_str);
        let _ = extract_log_fields(log_str);
    }
});
