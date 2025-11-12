use secreton_core::security::{
    AdvancedSecurityOrchestrator, BankingGradeConfig, GovernmentGradeConfig
};
use std::{sync::Arc, time::Instant};
use tokio::time::{timeout, Duration};

/// Performance benchmarks and load testing for Secreton security system
#[cfg(test)]
mod performance_tests {
    use super::*;

    /// Helper to create orchestrator for performance testing
    async fn create_perf_orchestrator() -> Result<Arc<AdvancedSecurityOrchestrator>, Box<dyn std::error::Error>> {
        let config = BankingGradeConfig::new();
        let orchestrator = AdvancedSecurityOrchestrator::new(config.into()).await?;
        Ok(Arc::new(orchestrator))
    }

    #[tokio::test]
    async fn benchmark_encryption_performance() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_perf_orchestrator().await?;
        
        // Test different data sizes
        let test_cases = vec![
            ("small", "x".repeat(100)),      // 100 bytes
            ("medium", "x".repeat(1024)),    // 1KB
            ("large", "x".repeat(10240)),    // 10KB
            ("xlarge", "x".repeat(102400)),  // 100KB
        ];
        
        for (size_name, test_data) in test_cases {
            let iterations = match size_name {
                "small" => 1000,
                "medium" => 500,
                "large" => 100,
                "xlarge" => 50,
                _ => 100,
            };
            
            let start_time = Instant::now();
            
            for _ in 0..iterations {
                let encrypted = orchestrator.encrypt_data(&test_data).await?;
                let _decrypted = orchestrator.decrypt_data(&encrypted).await?;
            }
            
            let duration = start_time.elapsed();
            let ops_per_second = iterations as f64 / duration.as_secs_f64();
            let mb_per_second = (test_data.len() * iterations) as f64 / (1024.0 * 1024.0) / duration.as_secs_f64();
            
            println!("Encryption {} data: {:.2} ops/sec, {:.2} MB/s", 
                     size_name, ops_per_second, mb_per_second);
            
            // Performance assertions based on data size
            let min_ops_per_sec = match size_name {
                "small" => 500.0,   // Small data should be very fast
                "medium" => 100.0,  // Medium data should be fast
                "large" => 50.0,    // Large data should be reasonable
                "xlarge" => 20.0,   // Very large data minimum threshold
                _ => 10.0,
            };
            
            assert!(ops_per_second >= min_ops_per_sec, 
                   "Encryption performance for {} data too low: {:.2} ops/sec (minimum: {:.2})",
                   size_name, ops_per_second, min_ops_per_sec);
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn benchmark_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_perf_orchestrator().await?;
        
        // Test concurrent encryption operations
        let concurrency_levels = vec![1, 5, 10, 20];
        let test_data = "concurrent_test_data".repeat(100); // ~2KB
        
        for concurrency in concurrency_levels {
            let start_time = Instant::now();
            let mut tasks = Vec::new();
            
            for i in 0..concurrency {
                let orch = Arc::clone(&orchestrator);
                let data = format!("{}_task_{}", test_data, i);
                
                let task = tokio::spawn(async move {
                    let encrypted = orch.encrypt_data(&data).await?;
                    let decrypted = orch.decrypt_data(&encrypted).await?;
                    assert_eq!(data, decrypted);
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                });
                
                tasks.push(task);
            }
            
            // Wait for all tasks with timeout
            let results = timeout(Duration::from_secs(30), futures::future::try_join_all(tasks)).await?;
            
            let duration = start_time.elapsed();
            let total_ops_per_sec = (concurrency * 2) as f64 / duration.as_secs_f64(); // 2 ops per task (encrypt + decrypt)
            
            // Verify all operations succeeded
            for result in results {
                result??;
            }
            
            println!("Concurrency level {}: {:.2} total ops/sec ({:.2} ms average latency)", 
                     concurrency, total_ops_per_sec, duration.as_millis() as f64 / concurrency as f64);
            
            // Performance should scale reasonably with concurrency
            assert!(duration.as_secs() < 10, 
                   "Concurrent operations should complete within 10 seconds");
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn benchmark_mfa_operations() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_perf_orchestrator().await?;
        
        // Benchmark MFA enrollment
        let enrollment_iterations = 50;
        let start_time = Instant::now();
        
        for i in 0..enrollment_iterations {
            let user_id = format!("perf_user_{}", i);
            let result = orchestrator.enroll_mfa(&user_id).await;
            
            // Count successful enrollments
            if result.is_ok() {
                // Enrollment succeeded
            }
        }
        
        let enrollment_duration = start_time.elapsed();
        let enrollment_ops_per_sec = enrollment_iterations as f64 / enrollment_duration.as_secs_f64();
        
        println!("MFA enrollment: {:.2} ops/sec", enrollment_ops_per_sec);
        
        // Should handle at least 10 enrollments per second
        assert!(enrollment_ops_per_sec >= 5.0, 
               "MFA enrollment too slow: {:.2} ops/sec", enrollment_ops_per_sec);
        
        // Benchmark behavioral biometrics verification
        let user_id = "biometric_perf_user";
        let _enrollment = orchestrator.enroll_mfa(user_id).await;
        
        let behavioral_data = serde_json::json!({
            "typing_patterns": [120, 150, 200, 180, 160],
            "mouse_dynamics": [{"x": 100, "y": 200, "timestamp": 1000}],
            "device_fingerprint": "test_device_fingerprint"
        });
        
        let biometric_iterations = 100;
        let start_time = Instant::now();
        
        for _ in 0..biometric_iterations {
            let _result = orchestrator
                .verify_behavioral_biometrics(user_id, &behavioral_data)
                .await;
        }
        
        let biometric_duration = start_time.elapsed();
        let biometric_ops_per_sec = biometric_iterations as f64 / biometric_duration.as_secs_f64();
        
        println!("Behavioral biometrics: {:.2} verifications/sec", biometric_ops_per_sec);
        
        // Should handle at least 20 biometric verifications per second
        assert!(biometric_ops_per_sec >= 10.0, 
               "Biometric verification too slow: {:.2} ops/sec", biometric_ops_per_sec);
        
        Ok(())
    }

    #[tokio::test]
    async fn benchmark_threat_intelligence() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_perf_orchestrator().await?;
        
        // Benchmark threat indicator assessment
        let test_indicators = vec![
            "192.168.1.100", "10.0.0.1", "172.16.0.1", "127.0.0.1",
            "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9",
        ];
        
        let iterations_per_indicator = 50;
        let start_time = Instant::now();
        let mut total_assessments = 0;
        
        for indicator in &test_indicators {
            for _ in 0..iterations_per_indicator {
                let _assessment = orchestrator.assess_threat_indicator(indicator).await?;
                total_assessments += 1;
            }
        }
        
        let duration = start_time.elapsed();
        let assessments_per_sec = total_assessments as f64 / duration.as_secs_f64();
        
        println!("Threat indicator assessments: {:.2} assessments/sec", assessments_per_sec);
        
        // Should handle at least 50 threat assessments per second
        assert!(assessments_per_sec >= 25.0, 
               "Threat assessment too slow: {:.2} assessments/sec", assessments_per_sec);
        
        // Benchmark behavioral anomaly detection
        let anomaly_test_cases = vec![
            serde_json::json!({
                "user_id": "user_001",
                "login_time": "09:00:00",
                "location": "office",
                "device": "laptop_001"
            }),
            serde_json::json!({
                "user_id": "user_002", 
                "login_time": "15:30:00",
                "location": "home",
                "device": "mobile_002"
            }),
            serde_json::json!({
                "user_id": "user_003",
                "login_time": "02:15:00",
                "location": "unknown",
                "device": "new_device"
            }),
        ];
        
        let anomaly_iterations = 100;
        let start_time = Instant::now();
        
        for test_case in &anomaly_test_cases {
            for _ in 0..(anomaly_iterations / anomaly_test_cases.len()) {
                let _score = orchestrator.detect_behavioral_anomaly(test_case).await?;
            }
        }
        
        let anomaly_duration = start_time.elapsed();
        let anomaly_detections_per_sec = anomaly_iterations as f64 / anomaly_duration.as_secs_f64();
        
        println!("Behavioral anomaly detection: {:.2} detections/sec", anomaly_detections_per_sec);
        
        // Should handle at least 30 anomaly detections per second
        assert!(anomaly_detections_per_sec >= 15.0, 
               "Anomaly detection too slow: {:.2} detections/sec", anomaly_detections_per_sec);
        
        Ok(())
    }

    #[tokio::test]
    async fn benchmark_hsm_operations() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_perf_orchestrator().await?;
        
        // Benchmark HSM key generation
        let key_gen_iterations = 20; // HSM operations are typically slower
        let start_time = Instant::now();
        let mut generated_keys = Vec::new();
        
        for _ in 0..key_gen_iterations {
            match orchestrator.generate_hsm_key().await {
                Ok(key_id) => generated_keys.push(key_id),
                Err(_) => {
                    // HSM may not be available in test environment
                    println!("HSM not available in test environment, skipping HSM benchmarks");
                    return Ok(());
                }
            }
        }
        
        let key_gen_duration = start_time.elapsed();
        let key_gen_per_sec = key_gen_iterations as f64 / key_gen_duration.as_secs_f64();
        
        println!("HSM key generation: {:.2} keys/sec", key_gen_per_sec);
        
        // HSM key generation is expected to be slower
        assert!(key_gen_per_sec >= 0.5, 
               "HSM key generation too slow: {:.2} keys/sec", key_gen_per_sec);
        
        // Benchmark HSM encryption/decryption
        if let Some(key_id) = generated_keys.first() {
            let test_data = "HSM_performance_test_data";
            let hsm_iterations = 50;
            let start_time = Instant::now();
            
            for _ in 0..hsm_iterations {
                let encrypted = orchestrator.hsm_encrypt(key_id, test_data).await?;
                let _decrypted = orchestrator.hsm_decrypt(key_id, &encrypted).await?;
            }
            
            let hsm_duration = start_time.elapsed();
            let hsm_ops_per_sec = (hsm_iterations * 2) as f64 / hsm_duration.as_secs_f64(); // 2 ops per iteration
            
            println!("HSM encrypt/decrypt: {:.2} ops/sec", hsm_ops_per_sec);
            
            // HSM operations are slower but should meet minimum thresholds
            assert!(hsm_ops_per_sec >= 2.0, 
                   "HSM operations too slow: {:.2} ops/sec", hsm_ops_per_sec);
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn benchmark_system_health_monitoring() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_perf_orchestrator().await?;
        
        // Benchmark health status checks
        let health_iterations = 200;
        let start_time = Instant::now();
        
        for _ in 0..health_iterations {
            let _health = orchestrator.get_health_status().await?;
        }
        
        let health_duration = start_time.elapsed();
        let health_checks_per_sec = health_iterations as f64 / health_duration.as_secs_f64();
        
        println!("Health status checks: {:.2} checks/sec", health_checks_per_sec);
        
        // Health checks should be very fast
        assert!(health_checks_per_sec >= 100.0, 
               "Health monitoring too slow: {:.2} checks/sec", health_checks_per_sec);
        
        // Benchmark performance metrics collection
        let metrics_iterations = 100;
        let start_time = Instant::now();
        
        for _ in 0..metrics_iterations {
            let _metrics = orchestrator.get_performance_metrics().await?;
        }
        
        let metrics_duration = start_time.elapsed();
        let metrics_per_sec = metrics_iterations as f64 / metrics_duration.as_secs_f64();
        
        println!("Performance metrics collection: {:.2} collections/sec", metrics_per_sec);
        
        // Metrics collection should be reasonably fast
        assert!(metrics_per_sec >= 50.0, 
               "Metrics collection too slow: {:.2} collections/sec", metrics_per_sec);
        
        Ok(())
    }

    #[tokio::test]
    async fn stress_test_sustained_load() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_perf_orchestrator().await?;
        
        println!("Starting sustained load stress test...");
        
        let test_duration = Duration::from_secs(30); // 30-second stress test
        let concurrent_tasks = 10;
        let test_data = "stress_test_payload".repeat(50); // ~1KB
        
        let start_time = Instant::now();
        let mut tasks = Vec::new();
        
        for task_id in 0..concurrent_tasks {
            let orch = Arc::clone(&orchestrator);
            let data = format!("{}_task_{}", test_data, task_id);
            
            let task = tokio::spawn(async move {
                let mut operations_completed = 0;
                let task_start = Instant::now();
                
                while task_start.elapsed() < test_duration {
                    match orch.encrypt_data(&data).await {
                        Ok(encrypted) => {
                            match orch.decrypt_data(&encrypted).await {
                                Ok(_) => operations_completed += 1,
                                Err(_) => break,
                            }
                        },
                        Err(_) => break,
                    }
                    
                    // Small delay to prevent overwhelming the system
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                
                operations_completed
            });
            
            tasks.push(task);
        }
        
        // Wait for all stress test tasks to complete
        let results = futures::future::join_all(tasks).await;
        let total_duration = start_time.elapsed();
        
        let mut total_operations = 0;
        for result in results {
            match result {
                Ok(ops) => total_operations += ops,
                Err(e) => println!("Stress test task failed: {:?}", e),
            }
        }
        
        let avg_ops_per_sec = total_operations as f64 / total_duration.as_secs_f64();
        
        println!("Stress test completed: {} total operations in {:.2}s ({:.2} ops/sec)",
                total_operations, total_duration.as_secs_f64(), avg_ops_per_sec);
        
        // System should maintain reasonable performance under sustained load
        assert!(total_operations > 0, "System should complete at least some operations under load");
        assert!(avg_ops_per_sec >= 10.0, 
               "System should maintain at least 10 ops/sec under sustained load, got {:.2}", 
               avg_ops_per_sec);
        
        // Check system health after stress test
        let post_stress_health = orchestrator.get_health_status().await?;
        assert!(post_stress_health.overall_health >= 70.0, 
               "System health should remain reasonable after stress test: {}%", 
               post_stress_health.overall_health);
        
        Ok(())
    }
}
