#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::api_gateway::{ApiRequest, ApiResponse, Route, RateLimit, RateLimitAlgorithm};
use secreton_core::services::request_forwarding::{ForwardRequest, ForwardResponse, ClusterNode, NodeRole};
use serde_json;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

fuzz_target!(|data: &[u8]| {
    // Test network protocol structures and serialization
    if data.len() < 50 {
        return;
    }

    // Test ApiRequest parsing and creation
    if let Ok(request_str) = std::str::from_utf8(data) {
        // Try to parse as JSON for ApiRequest
        let _ = serde_json::from_str::<ApiRequest>(request_str);

        // Create ApiRequest from fuzzed data
        let request = ApiRequest {
            request_id: format!("req_{}", data.len()),
            method: "GET".to_string(),
            path: "/test".to_string(),
            headers: HashMap::new(),
            tenant_id: Some("test_tenant".to_string()),
            timestamp: Utc::now(),
        };

        // Test JSON serialization
        let _ = serde_json::to_string(&request);

        // Test ApiResponse creation and serialization
        let response = ApiResponse {
            request_id: request.request_id.clone(),
            status_code: 200,
            body: data.to_vec(),
            headers: HashMap::new(),
            latency_ms: 100,
        };
        let _ = serde_json::to_string(&response);
    }

    // Test ForwardRequest creation
    let forward_request = ForwardRequest {
        id: format!("fwd_{}", data.len()),
        method: "POST".to_string(),
        path: "/forward".to_string(),
        headers: HashMap::new(),
        body: Some(data.to_vec()),
        source_node: "node1".to_string(),
        target_node: Some("node2".to_string()),
        created_at: Utc::now(),
    };
    let _ = serde_json::to_string(&forward_request);

    // Test ForwardResponse creation
    let forward_response = ForwardResponse {
        request_id: forward_request.id.clone(),
        status_code: 200,
        headers: HashMap::new(),
        body: Some(data.to_vec()),
        forwarded_by: "node1".to_string(),
        processed_at: Utc::now(),
    };
    let _ = serde_json::to_string(&forward_response);

    // Test ClusterNode creation
    let cluster_node = ClusterNode {
        node_id: "test_node".to_string(),
        address: "127.0.0.1:8200".to_string(),
        role: NodeRole::Leader,
        is_active: true,
        last_heartbeat: Utc::now(),
        api_address: "127.0.0.1:8200".to_string(),
        cluster_address: "127.0.0.1:8201".to_string(),
    };
    let _ = serde_json::to_string(&cluster_node);

    // Test Route creation
    let route = Route {
        route_id: "test_route".to_string(),
        path_pattern: "/api/*".to_string(),
        backend_url: "http://backend:8080".to_string(),
        methods: vec!["GET".to_string(), "POST".to_string()],
        rate_limit: Some(RateLimit {
            algorithm: RateLimitAlgorithm::TokenBucket,
            requests_per_second: 100,
            burst_size: 10,
        }),
        authentication_required: true,
    };
    let _ = serde_json::to_string(&route);
});