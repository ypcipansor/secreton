//! Common test utilities and helper functions for Brankas tests

use std::{sync::Arc, time::Duration};
use serde_json::{json, Value};

/// Test configuration and setup utilities
pub mod test_config {
    use super::*;
    
    /// Create standard test configuration for banking-grade security
    pub fn banking_test_config() -> Value {
        json!({
            "security_level": "banking",
            "compliance": {
                "pci_dss": true,
                "sox": true,
                "basel_iii": true
            },
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_size": 256
            },
            "audit": {
                "enabled": true,
                "level": "detailed"
            }
        })
    }
    
    /// Create standard test configuration for government-grade security
    pub fn government_test_config() -> Value {
        json!({
            "security_level": "government",
            "compliance": {
                "fips_140_2": true,
                "common_criteria": true
            },
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_size": 256,
                "quantum_safe": true
            },
            "audit": {
                "enabled": true,
                "level": "comprehensive"
            }
        })
    }
}

/// Mock storage implementations for testing
pub mod test_storage {
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    
    /// Simple in-memory storage for testing
    #[derive(Debug, Clone, Default)]
    pub struct InMemoryStorage {
        data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
        metadata: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    }
    
    impl InMemoryStorage {
        pub fn new() -> Self {
            Self::default()
        }
        
        pub async fn store(&self, key: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
            self.data.write().unwrap().insert(key.to_string(), data.to_vec());
            Ok(())
        }
        
        pub async fn retrieve(&self, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            self.data
                .read()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| "Key not found".into())
        }
        
        pub async fn delete(&self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.data.write().unwrap().remove(key);
            self.metadata.write().unwrap().remove(key);
            Ok(())
        }
        
        pub async fn list_keys(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
            Ok(self.data.read().unwrap().keys().cloned().collect())
        }
        
        pub async fn store_metadata(&self, key: &str, metadata: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
            self.metadata.write().unwrap().insert(key.to_string(), metadata.clone());
            Ok(())
        }
        
        pub async fn get_metadata(&self, key: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
            self.metadata
                .read()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| "Metadata not found".into())
        }
    }
}

/// Test data generators and utilities
pub mod test_data {
    use super::*;
    use rand::{Rng, thread_rng};
    
    /// Generate test data of specified size
    pub fn generate_test_data(size: usize) -> String {
        (0..size)
            .map(|_| thread_rng().gen_range(b'A'..=b'Z') as char)
            .collect()
    }
    
    /// Generate test secrets with various characteristics
    pub fn generate_test_secrets() -> Vec<(&'static str, String)> {
        vec![
            ("small_secret", "secret123".to_string()),
            ("medium_secret", "x".repeat(100)),
            ("large_secret", "y".repeat(1000)),
            ("binary_secret", (0..64).map(|i| (i % 256) as u8 as char).collect()),
            ("unicode_secret", "🔐🔑🛡️💎🎯".to_string()),
            ("json_secret", r#"{"api_key": "abc123", "token": "xyz789"}"#.to_string()),
        ]
    }
    
    /// Generate test user data for authentication tests
    pub fn generate_test_users() -> Vec<serde_json::Value> {
        vec![
            json!({
                "user_id": "admin_user",
                "role": "administrator",
                "permissions": ["read", "write", "delete", "admin"],
                "mfa_enabled": true
            }),
            json!({
                "user_id": "regular_user",
                "role": "user",
                "permissions": ["read", "write"],
                "mfa_enabled": true
            }),
            json!({
                "user_id": "readonly_user",
                "role": "viewer",
                "permissions": ["read"],
                "mfa_enabled": false
            }),
            json!({
                "user_id": "service_account",
                "role": "service",
                "permissions": ["read", "write"],
                "mfa_enabled": false,
                "service_type": "api_integration"
            }),
        ]
    }
    
    /// Generate behavioral biometric test data
    pub fn generate_biometric_data(user_type: &str) -> serde_json::Value {
        match user_type {
            "normal" => json!({
                "typing_patterns": {
                    "average_dwell_time": 150,
                    "average_flight_time": 100,
                    "key_intervals": [120, 130, 140, 160, 155],
                    "variance": 0.15
                },
                "mouse_dynamics": {
                    "velocity": 2.5,
                    "acceleration": [1.2, 1.5, 1.8],
                    "click_pattern": "regular"
                },
                "device_fingerprint": {
                    "screen_resolution": "1920x1080",
                    "timezone": "UTC",
                    "user_agent": "test_browser"
                }
            }),
            "suspicious" => json!({
                "typing_patterns": {
                    "average_dwell_time": 80,  // Too fast
                    "average_flight_time": 50,  // Too fast
                    "key_intervals": [50, 45, 55, 40, 48], // Consistent (bot-like)
                    "variance": 0.02  // Too low variance
                },
                "mouse_dynamics": {
                    "velocity": 10.0,  // Too fast
                    "acceleration": [5.0, 5.0, 5.0], // Too consistent
                    "click_pattern": "rapid"
                },
                "device_fingerprint": {
                    "screen_resolution": "800x600", // Unusual
                    "timezone": "unknown",
                    "user_agent": "automated_tool"
                }
            }),
            _ => json!({"error": "unknown_user_type"}),
        }
    }
}

/// Performance testing utilities
pub mod performance_utils {
    use super::*;
    use std::time::Instant;
    
    /// Measure execution time of an async operation
    pub async fn measure_async<F, T>(operation: F) -> (T, Duration)
    where
        F: std::future::Future<Output = T>,
    {
        let start = Instant::now();
        let result = operation.await;
        let duration = start.elapsed();
        (result, duration)
    }
    
    /// Run performance benchmark with multiple iterations
    pub async fn benchmark_operation<F, T>(
        operation_name: &str,
        iterations: usize,
        operation: F,
    ) -> BenchmarkResult
    where
        F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Box<dyn std::error::Error>>> + Send>>,
    {
        let mut durations = Vec::new();
        let mut successful_operations = 0;
        let mut failed_operations = 0;
        
        let total_start = Instant::now();
        
        for _ in 0..iterations {
            let (result, duration) = measure_async(operation()).await;
            durations.push(duration);
            
            match result {
                Ok(_) => successful_operations += 1,
                Err(_) => failed_operations += 1,
            }
        }
        
        let total_duration = total_start.elapsed();
        
        // Calculate statistics
        durations.sort();
        let avg_duration = durations.iter().sum::<Duration>() / durations.len() as u32;
        let median_duration = durations[durations.len() / 2];
        let p95_duration = durations[(durations.len() as f64 * 0.95) as usize];
        let p99_duration = durations[(durations.len() as f64 * 0.99) as usize];
        
        BenchmarkResult {
            operation_name: operation_name.to_string(),
            total_iterations: iterations,
            successful_operations,
            failed_operations,
            total_duration,
            average_duration: avg_duration,
            median_duration,
            p95_duration,
            p99_duration,
            operations_per_second: successful_operations as f64 / total_duration.as_secs_f64(),
        }
    }
    
    #[derive(Debug, Clone)]
    pub struct BenchmarkResult {
        pub operation_name: String,
        pub total_iterations: usize,
        pub successful_operations: usize,
        pub failed_operations: usize,
        pub total_duration: Duration,
        pub average_duration: Duration,
        pub median_duration: Duration,
        pub p95_duration: Duration,
        pub p99_duration: Duration,
        pub operations_per_second: f64,
    }
    
    impl BenchmarkResult {
        pub fn print_summary(&self) {
            println!("\n=== {} Benchmark Results ===", self.operation_name);
            println!("Total iterations: {}", self.total_iterations);
            println!("Successful: {}, Failed: {}", self.successful_operations, self.failed_operations);
            println!("Total time: {:.2?}", self.total_duration);
            println!("Average: {:.2?}", self.average_duration);
            println!("Median: {:.2?}", self.median_duration);
            println!("95th percentile: {:.2?}", self.p95_duration);
            println!("99th percentile: {:.2?}", self.p99_duration);
            println!("Operations/second: {:.2}", self.operations_per_second);
            println!("================================\n");
        }
    }
}

/// Security test utilities
pub mod security_utils {
    use super::*;
    
    /// Generate test attack payloads for security testing
    pub fn generate_attack_payloads() -> Vec<(&'static str, String)> {
        vec![
            ("sql_injection", "'; DROP TABLE users; --".to_string()),
            ("xss_payload", "<script>alert('xss')</script>".to_string()),
            ("path_traversal", "../../../../etc/passwd".to_string()),
            ("command_injection", "; rm -rf / ; echo".to_string()),
            ("ldap_injection", "*)(&(objectclass=*))".to_string()),
            ("xml_bomb", "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">]><lolz>&lol;</lolz>".to_string()),
            ("buffer_overflow", "A".repeat(10000)),
            ("null_byte", "test\0.txt".to_string()),
            ("unicode_bypass", "\u{202e}".to_string()), // Right-to-left override
        ]
    }
    
    /// Validate that sensitive data doesn't leak in error messages
    pub fn validate_error_message(error_msg: &str, sensitive_data: &[&str]) -> bool {
        for sensitive in sensitive_data {
            if error_msg.contains(sensitive) {
                println!("WARNING: Sensitive data '{}' found in error message: {}", sensitive, error_msg);
                return false;
            }
        }
        true
    }
    
    /// Generate timing attack test data
    pub fn generate_timing_test_data() -> Vec<(String, String)> {
        vec![
            ("correct_length".to_string(), "secret123".to_string()),
            ("wrong_length_short".to_string(), "sec".to_string()),
            ("wrong_length_long".to_string(), "secret123456789".to_string()),
            ("correct_prefix".to_string(), "secret456".to_string()),
            ("wrong_all".to_string(), "wrongwrong".to_string()),
        ]
    }
}

/// Test assertion helpers
pub mod test_assertions {
    use super::*;
    
    /// Assert that operation completes within expected time
    pub fn assert_performance(duration: Duration, max_duration: Duration, operation: &str) {
        assert!(duration <= max_duration, 
               "{} took too long: {:.2?} (max: {:.2?})", 
               operation, duration, max_duration);
    }
    
    /// Assert that encrypted data has expected properties
    pub fn assert_encryption_properties(plaintext: &str, ciphertext: &str) {
        assert_ne!(plaintext, ciphertext, "Ciphertext should differ from plaintext");
        assert!(ciphertext.len() > plaintext.len(), "Ciphertext should be longer than plaintext");
        
        // Should not contain obvious patterns
        assert!(!ciphertext.contains(plaintext), "Ciphertext should not contain plaintext");
        assert!(!ciphertext.contains("password"), "Ciphertext should not contain sensitive keywords");
    }
    
    /// Assert that random data has good entropy
    pub fn assert_entropy_quality(data: &[u8], min_quality: f64) {
        if data.is_empty() {
            panic!("Cannot assess entropy of empty data");
        }
        
        // Simple entropy calculation (Shannon entropy)
        let mut byte_counts = [0u32; 256];
        for &byte in data {
            byte_counts[byte as usize] += 1;
        }
        
        let mut entropy = 0.0;
        let data_len = data.len() as f64;
        
        for count in byte_counts.iter().filter(|&&c| c > 0) {
            let probability = *count as f64 / data_len;
            entropy -= probability * probability.log2();
        }
        
        let max_entropy = 8.0; // Maximum possible entropy for bytes
        let quality = entropy / max_entropy;
        
        assert!(quality >= min_quality, 
               "Data entropy quality too low: {:.3} (minimum: {:.3})", 
               quality, min_quality);
    }
    
    /// Assert compliance with security standards
    pub fn assert_security_compliance(compliance_status: &serde_json::Value, required_standards: &[&str]) {
        for standard in required_standards {
            let compliant = compliance_status
                .get(standard)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            
            assert!(compliant, "System should be compliant with {}", standard);
        }
    }
}

/// Create test storage instance
pub fn create_test_storage() -> Arc<test_storage::InMemoryStorage> {
    Arc::new(test_storage::InMemoryStorage::new())
}

/// Test utilities module re-exports
pub use test_config::*;
pub use test_data::*;
pub use performance_utils::*;
pub use security_utils::*;
pub use test_assertions::*;
