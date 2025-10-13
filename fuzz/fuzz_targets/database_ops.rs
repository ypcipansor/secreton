#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::secrets::database::*;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Test database operation parsing and validation
    if data.len() < 100 {
        return;
    }

    // Split data for different database operations
    let path_end = data.len() / 4;
    let data_end = 2 * data.len() / 4;
    let query_end = 3 * data.len() / 4;

    let path = &data[..path_end];
    let secret_data = &data[path_end..data_end];
    let query = &data[data_end..query_end];
    let connection_info = &data[query_end..];

    // Test path validation
    if let Ok(path_str) = std::str::from_utf8(path) {
        let _ = validate_database_path(path_str);
        let _ = parse_database_path(path_str);
    }

    // Test secret data parsing
    if let Ok(data_str) = std::str::from_utf8(secret_data) {
        if let Ok(secret_map) = serde_json::from_str::<HashMap<String, String>>(data_str) {
            let _ = validate_secret_data(&secret_map);
            let _ = sanitize_secret_data(&secret_map);
        }
    }

    // Test query parsing
    if let Ok(query_str) = std::str::from_utf8(query) {
        let _ = parse_database_query(query_str);
        let _ = validate_query_parameters(query_str);
    }

    // Test connection info parsing
    if let Ok(conn_str) = std::str::from_utf8(connection_info) {
        let _ = parse_connection_string(conn_str);
        let _ = validate_connection_parameters(conn_str);
    }
});