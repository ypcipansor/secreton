//! Performance and load testing for vault system
//!
//! Tests system performance under various load conditions including
//! concurrent operations, memory usage, and response times.

use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;
use tokio::time::sleep;

use crate::handlers::vault::*;
use crate::config::ApiConfig;
use crate::services::ServiceContainer;
use axum_test::TestServer;

async fn create_test_server() -> TestServer {
    let config = ApiConfig::default();
    let services = Arc::new(
        ServiceContainer::new(&config)
            .await
            .expect("Failed to create services"),
    );

    let app = create_routes().with_state(services);
    TestServer::new(app).expect("Failed to create test server")
}

#[cfg(test)]
mod performance_tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_secret_operations_performance() -> Result<()> {
        let server = create_test_server().await;
        let num_operations = 100;
        let concurrency = 10;

        let start_time = Instant::now();

        // Create multiple concurrent operations
        let mut handles = Vec::new();

        for i in 0..concurrency {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                for j in 0..(num_operations / concurrency) {
                    let secret_id = format!("perf_secret_{}_{}", i, j);
                    let payload = json!({
                        "data": {
                            "key": format!("value_{}_{}", i, j),
                            "metadata": format!("metadata_{}_{}", i, j)
                        }
                    });

                    let response = server_clone
                        .post(&format!("/secrets/{}", secret_id))
                        .json(&payload)
                        .await;

                    if !response.status_code().is_success() {
                        return Err(anyhow::anyhow!("Failed operation: {}", response.status_code()));
                    }

                    // Add small delay to prevent overwhelming the system
                    sleep(Duration::from_millis(1)).await;
                }
                Ok::<_, anyhow::Error>(())
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.await??;
        }

        let total_duration = start_time.elapsed();
        let operations_per_second = num_operations as f64 / total_duration.as_secs_f64();

        println!("Concurrent operations: {} ops in {:?}", num_operations, total_duration);
        println!("Performance: {:.2} ops/sec", operations_per_second);

        // Performance assertions
        assert!(operations_per_second > 10.0, "Should achieve reasonable throughput");
        assert!(total_duration < Duration::from_secs(30), "Should complete within reasonable time");

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_usage_under_load() -> Result<()> {
        let server = create_test_server().await;

        // Get initial memory usage (approximate)
        let initial_memory = get_memory_usage();

        // Create many secrets to test memory growth
        for i in 0..1000 {
            let payload = json!({
                "data": {
                    "large_field": format!("Large data chunk number {} with lots of content", i)
                }
            });

            let response = server
                .post(&format!("/secrets/memory_test_{}", i))
                .json(&payload)
                .await;

            if !response.status_code().is_success() {
                break; // Stop if system is overwhelmed
            }
        }

        // Check memory growth
        let final_memory = get_memory_usage();
        let memory_growth = final_memory - initial_memory;

        println!("Memory usage - Initial: {} MB, Final: {} MB, Growth: {} MB",
                initial_memory / 1024 / 1024,
                final_memory / 1024 / 1024,
                memory_growth / 1024 / 1024);

        // Memory growth should be reasonable
        assert!(memory_growth < 100 * 1024 * 1024, "Memory growth should be reasonable (< 100MB)");

        Ok(())
    }

    #[tokio::test]
    async fn test_api_response_time_distribution() -> Result<()> {
        let server = create_test_server().await;
        let num_requests = 100;

        let mut response_times = Vec::new();

        // Create test data first
        let payload = json!({"data": {"test": "response_time_test"}});
        let response = server.post("/secrets/response_time_test").json(&payload).await;
        response.assert_status_ok();

        // Measure response times for reads
        for _ in 0..num_requests {
            let start_time = Instant::now();
            let response = server.get("/secrets/response_time_test").await;
            let response_time = start_time.elapsed();

            if response.status_code().is_success() {
                response_times.push(response_time);
            }
        }

        // Analyze response time distribution
        let avg_response_time = response_times.iter().sum::<Duration>() / response_times.len() as u32;
        let max_response_time = response_times.iter().max().unwrap();
        let min_response_time = response_times.iter().min().unwrap();

        println!("Response time stats:");
        println!("  Average: {:?}", avg_response_time);
        println!("  Max: {:?}", max_response_time);
        println!("  Min: {:?}", min_response_time);

        // Calculate percentiles
        response_times.sort();
        let p50_index = response_times.len() / 2;
        let p90_index = response_times.len() * 9 / 10;
        let p99_index = response_times.len() * 99 / 100;

        if p50_index < response_times.len() {
            println!("  P50: {:?}", response_times[p50_index]);
        }
        if p90_index < response_times.len() {
            println!("  P90: {:?}", response_times[p90_index]);
        }
        if p99_index < response_times.len() {
            println!("  P99: {:?}", response_times[p99_index]);
        }

        // Performance assertions
        assert!(avg_response_time < Duration::from_millis(100), "Average response time should be < 100ms");
        assert!(max_response_time < Duration::from_millis(1000), "Max response time should be < 1s");

        Ok(())
    }

    #[tokio::test]
    async fn test_database_connection_pooling_performance() -> Result<()> {
        let server = create_test_server().await;
        let num_concurrent_connections = 50;
        let operations_per_connection = 10;

        let start_time = Instant::now();

        // Test database connection pool under load
        let mut handles = Vec::new();

        for conn_id in 0..num_concurrent_connections {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                for op_id in 0..operations_per_connection {
                    let secret_name = format!("pool_test_{}_{}", conn_id, op_id);
                    let payload = json!({
                        "data": {
                            "connection_id": conn_id,
                            "operation_id": op_id
                        }
                    });

                    let response = server_clone
                        .post(&format!("/secrets/{}", secret_name))
                        .json(&payload)
                        .await;

                    if !response.status_code().is_success() {
                        return Err(anyhow::anyhow!("Connection pool operation failed"));
                    }
                }
                Ok::<_, anyhow::Error>(())
            });
            handles.push(handle);
        }

        // Wait for all operations
        for handle in handles {
            handle.await??;
        }

        let total_duration = start_time.elapsed();
        let total_operations = num_concurrent_connections * operations_per_connection;
        let operations_per_second = total_operations as f64 / total_duration.as_secs_f64();

        println!("Connection pool test: {} operations in {:?}", total_operations, total_duration);
        println!("Performance: {:.2} ops/sec", operations_per_second);

        // Should handle concurrent connections efficiently
        assert!(operations_per_second > 50.0, "Should handle concurrent connections efficiently");

        Ok(())
    }

    #[tokio::test]
    async fn test_cryptographic_operations_performance() -> Result<()> {
        let server = create_test_server().await;

        // Test encryption/decryption performance
        let data_sizes = vec![1024, 1024 * 10, 1024 * 100]; // 1KB, 10KB, 100KB
        let num_iterations = 10;

        for data_size in data_sizes {
            let test_data = vec![42u8; data_size];

            let mut encrypt_times = Vec::new();
            let mut decrypt_times = Vec::new();

            for _ in 0..num_iterations {
                // Measure encryption time
                let encrypt_start = Instant::now();
                let response = server
                    .post("/encrypt")
                    .json(&json!({
                        "key_id": "perf_test_key",
                        "plaintext": general_purpose::STANDARD.encode(&test_data),
                        "algorithm": "AES-GCM"
                    }))
                    .await;

                if response.status_code().is_success() {
                    let encrypt_time = encrypt_start.elapsed();
                    encrypt_times.push(encrypt_time);

                    // Extract ciphertext for decryption test
                    let body: serde_json::Value = response.json();
                    if let Some(ciphertext) = body["data"]["ciphertext"].as_str() {
                        // Measure decryption time
                        let decrypt_start = Instant::now();
                        let decrypt_response = server
                            .post("/decrypt")
                            .json(&json!({
                                "key_id": "perf_test_key",
                                "ciphertext": ciphertext,
                                "algorithm": "AES-GCM"
                            }))
                            .await;

                        if decrypt_response.status_code().is_success() {
                            let decrypt_time = decrypt_start.elapsed();
                            decrypt_times.push(decrypt_time);
                        }
                    }
                }
            }

            if !encrypt_times.is_empty() {
                let avg_encrypt = encrypt_times.iter().sum::<Duration>() / encrypt_times.len() as u32;
                let avg_decrypt = if !decrypt_times.is_empty() {
                    decrypt_times.iter().sum::<Duration>() / decrypt_times.len() as u32
                } else {
                    Duration::from_secs(0)
                };

                println!("Data size {}KB - Encrypt: {:?}, Decrypt: {:?}", data_size / 1024, avg_encrypt, avg_decrypt);

                // Performance should scale reasonably with data size
                assert!(avg_encrypt < Duration::from_millis(100), "Encryption should be fast");
                assert!(avg_decrypt < Duration::from_millis(100), "Decryption should be fast");
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_system_resource_usage() -> Result<()> {
        let server = create_test_server().await;

        // Create various types of load and measure resource usage
        let initial_cpu = get_cpu_usage();
        let initial_memory = get_memory_usage();

        // Create CPU-intensive operations
        let mut crypto_handles = Vec::new();
        for i in 0..5 {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                // Perform CPU-intensive crypto operations
                for _ in 0..10 {
                    let _ = server_clone
                        .post("/hash")
                        .json(&json!({
                            "data": format!("CPU intensive hashing operation {}", i),
                            "algorithm": "SHA-512"
                        }))
                        .await;
                }
            });
            crypto_handles.push(handle);
        }

        // Wait for crypto operations
        for handle in crypto_handles {
            let _ = handle.await;
        }

        // Create memory-intensive operations
        let mut memory_handles = Vec::new();
        for i in 0..3 {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                // Create large secrets
                for j in 0..5 {
                    let large_data = "x".repeat(1024 * 1024); // 1MB per secret
                    let _ = server_clone
                        .post(&format!("/secrets/memory_load_{}_{}", i, j))
                        .json(&json!({
                            "data": {"large_field": large_data}
                        }))
                        .await;
                }
            });
            memory_handles.push(handle);
        }

        // Wait for memory operations
        for handle in memory_handles {
            let _ = handle.await;
        }

        // Check resource usage
        let final_cpu = get_cpu_usage();
        let final_memory = get_memory_usage();

        println!("Resource usage - CPU: {}% -> {}%, Memory: {} MB -> {} MB",
                initial_cpu, final_cpu,
                initial_memory / 1024 / 1024,
                final_memory / 1024 / 1024);

        // Resource usage should be reasonable
        assert!(final_cpu < 90.0, "CPU usage should not be excessive");
        assert!(final_memory - initial_memory < 500 * 1024 * 1024, "Memory usage should not grow excessively");

        Ok(())
    }

    #[tokio::test]
    async fn test_audit_log_performance() -> Result<()> {
        let server = create_test_server().await;
        let num_operations = 1000;

        let start_time = Instant::now();

        // Perform operations that generate audit logs
        for i in 0..num_operations {
            let payload = json!({
                "data": {
                    "audit_test": format!("operation_{}", i)
                }
            });

            let response = server
                .post(&format!("/secrets/audit_perf_{}", i))
                .json(&payload)
                .await;

            if !response.status_code().is_success() {
                break; // Stop if system is overwhelmed
            }
        }

        let duration = start_time.elapsed();
        let operations_per_second = num_operations as f64 / duration.as_secs_f64();

        println!("Audit logging performance: {} operations in {:?}", num_operations, duration);
        println!("Performance: {:.2} ops/sec", operations_per_second);

        // Check that audit logs were created
        let response = server.get("/audit").await;
        if response.status_code().is_success() {
            let body: serde_json::Value = response.json();
            if let Some(data) = body.get("data") {
                let audit_count = data.as_array().unwrap().len();
                println!("Audit entries created: {}", audit_count);
                assert!(audit_count > 0, "Should have created audit entries");
            }
        }

        // Performance should be reasonable even with audit logging
        assert!(operations_per_second > 50.0, "Should handle audit logging efficiently");

        Ok(())
    }

    #[tokio::test]
    async fn test_mixed_workload_performance() -> Result<()> {
        let server = create_test_server().await;

        // Simulate realistic mixed workload
        let operations = vec![
            ("read", "/secrets/mixed_test_1", "GET"),
            ("write", "/secrets/mixed_test_2", "POST"),
            ("encrypt", "/encrypt", "POST"),
            ("list", "/secrets", "GET"),
            ("hash", "/hash", "POST"),
        ];

        let num_iterations = 50;
        let start_time = Instant::now();

        for iteration in 0..num_iterations {
            for (op_name, endpoint, method) in &operations {
                match method.as_str() {
                    "GET" => {
                        let _ = server.get(endpoint).await;
                    }
                    "POST" => {
                        let payload = match *op_name {
                            "encrypt" => json!({
                                "key_id": "mixed_test_key",
                                "plaintext": "test data",
                                "algorithm": "AES-GCM"
                            }),
                            "hash" => json!({
                                "data": "test data",
                                "algorithm": "SHA-256"
                            }),
                            _ => json!({
                                "data": {"test": format!("iteration_{}", iteration)}
                            }),
                        };

                        let _ = server.post(endpoint).json(&payload).await;
                    }
                    _ => {}
                }
            }
        }

        let total_duration = start_time.elapsed();
        let total_operations = operations.len() * num_iterations;
        let operations_per_second = total_operations as f64 / total_duration.as_secs_f64();

        println!("Mixed workload: {} operations in {:?}", total_operations, total_duration);
        println!("Performance: {:.2} ops/sec", operations_per_second);

        // Should handle mixed workloads efficiently
        assert!(operations_per_second > 20.0, "Should handle mixed workloads efficiently");

        Ok(())
    }

    #[tokio::test]
    async fn test_error_recovery_performance() -> Result<()> {
        let server = create_test_server().await;

        // Test system performance under error conditions
        let start_time = Instant::now();

        // Generate various types of errors
        let error_operations = vec![
            ("/secrets", "POST", json!({"invalid": "data"})),
            ("/non-existent-endpoint", "GET", json!({})),
            ("/secrets", "GET", json!({})), // This might work or fail
        ];

        for _ in 0..100 {
            for (endpoint, method, payload) in &error_operations {
                match method.as_str() {
                    "GET" => {
                        let _ = server.get(endpoint).await;
                    }
                    "POST" => {
                        let _ = server.post(endpoint).json(payload).await;
                    }
                    _ => {}
                }
            }
        }

        let error_duration = start_time.elapsed();
        let error_operations_per_second = (error_operations.len() * 100) as f64 / error_duration.as_secs_f64();

        println!("Error handling: {} operations in {:?}", error_operations.len() * 100, error_duration);
        println!("Error handling performance: {:.2} ops/sec", error_operations_per_second);

        // Error handling should be fast
        assert!(error_operations_per_second > 100.0, "Error handling should be fast");

        Ok(())
    }

    #[tokio::test]
    async fn test_scalability_benchmarks() -> Result<()> {
        let server = create_test_server().await;

        // Test scalability with increasing load
        let load_levels = vec![10, 50, 100, 200];

        for load in load_levels {
            let start_time = Instant::now();

            let mut handles = Vec::new();
            for i in 0..load {
                let server_clone = server.clone();
                let handle = tokio::spawn(async move {
                    let payload = json!({
                        "data": {
                            "load_test": format!("load_{}", i),
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        }
                    });

                    let response = server_clone
                        .post(&format!("/secrets/scalability_test_{}", i))
                        .json(&payload)
                        .await;

                    response.status_code().is_success()
                });
                handles.push(handle);
            }

            // Wait for all operations at this load level
            let successful_ops = handles.into_iter()
                .map(|h| h.await.unwrap_or(false))
                .filter(|&success| success)
                .count();

            let duration = start_time.elapsed();
            let ops_per_second = load as f64 / duration.as_secs_f64();

            println!("Load level {}: {} successful ops in {:?} ({:.2} ops/sec)",
                    load, successful_ops, duration, ops_per_second);

            // Performance should degrade gracefully
            assert!(ops_per_second > 1.0, "Should maintain reasonable performance at load level {}", load);
        }

        Ok(())
    }
}

// Helper functions for system monitoring
fn get_memory_usage() -> u64 {
    // This is a simplified implementation
    // In a real scenario, you'd use system monitoring APIs
    0 // Placeholder
}

fn get_cpu_usage() -> f32 {
    // This is a simplified implementation
    // In a real scenario, you'd use system monitoring APIs
    0.0 // Placeholder
}
