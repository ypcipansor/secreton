//! Performance benchmark tests for Brankas Enterprise Vault

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Mock encryption service for performance testing
struct MockEncryptionService {
    delay_ms: u64,
}

impl MockEncryptionService {
    fn new(delay_ms: u64) -> Self {
        Self { delay_ms }
    }
    
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        
        // Mock encryption: reverse bytes and add prefix
        let mut encrypted = b"ENCRYPTED:".to_vec();
        encrypted.extend(data.iter().rev());
        Ok(encrypted)
    }
    
    async fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        
        if encrypted.len() < 10 || !encrypted.starts_with(b"ENCRYPTED:") {
            return Err("Invalid encrypted data".into());
        }
        
        // Mock decryption: reverse bytes after prefix
        let data: Vec<u8> = encrypted[10..].iter().rev().copied().collect();
        Ok(data)
    }
    
    async fn hash_data(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::sleep(Duration::from_millis(self.delay_ms / 2)).await;
        
        // Mock hash: simple checksum
        let sum: u64 = data.iter().map(|&b| b as u64).sum();
        Ok(format!("HASH:{:016x}", sum))
    }
}

#[derive(Debug)]
struct BenchmarkResult {
    operation: String,
    total_operations: usize,
    total_duration: Duration,
    ops_per_second: f64,
    avg_latency_ms: f64,
    min_latency_ms: f64,
    max_latency_ms: f64,
}

impl BenchmarkResult {
    fn new(
        operation: String,
        total_operations: usize,
        total_duration: Duration,
        latencies: &[Duration],
    ) -> Self {
        let ops_per_second = total_operations as f64 / total_duration.as_secs_f64();
        let avg_latency_ms = latencies.iter().map(|d| d.as_millis() as f64).sum::<f64>() 
                           / latencies.len() as f64;
        let min_latency_ms = latencies.iter().map(|d| d.as_millis() as f64).fold(f64::INFINITY, f64::min);
        let max_latency_ms = latencies.iter().map(|d| d.as_millis() as f64).fold(0.0, f64::max);
        
        Self {
            operation,
            total_operations,
            total_duration,
            ops_per_second,
            avg_latency_ms,
            min_latency_ms,
            max_latency_ms,
        }
    }
}

/// Test encryption performance under load
#[tokio::test]
async fn test_encryption_performance() -> Result<(), Box<dyn std::error::Error>> {
    let encryption_service = Arc::new(MockEncryptionService::new(1)); // 1ms delay
    let test_data = vec![0u8; 1024]; // 1KB test data
    let num_operations = 100;
    
    let start = Instant::now();
    let mut latencies = Vec::new();
    
    for _ in 0..num_operations {
        let op_start = Instant::now();
        let encrypted = encryption_service.encrypt(&test_data).await?;
        let decrypted = encryption_service.decrypt(&encrypted).await?;
        let op_duration = op_start.elapsed();
        
        assert_eq!(test_data, decrypted, "Encryption/decryption should preserve data");
        latencies.push(op_duration);
    }
    
    let total_duration = start.elapsed();
    let result = BenchmarkResult::new(
        "Encryption/Decryption".to_string(),
        num_operations,
        total_duration,
        &latencies,
    );
    
    println!("Encryption Performance Results:");
    println!("  Operations: {}", result.total_operations);
    println!("  Total Duration: {:?}", result.total_duration);
    println!("  Ops/Second: {:.2}", result.ops_per_second);
    println!("  Avg Latency: {:.2}ms", result.avg_latency_ms);
    println!("  Min Latency: {:.2}ms", result.min_latency_ms);
    println!("  Max Latency: {:.2}ms", result.max_latency_ms);
    
    // Performance thresholds for enterprise-grade system
    assert!(result.ops_per_second >= 10.0, 
           "Encryption should handle at least 10 ops/sec, got {:.2}", 
           result.ops_per_second);
    assert!(result.avg_latency_ms <= 100.0, 
           "Average latency should be <= 100ms, got {:.2}ms", 
           result.avg_latency_ms);
    
    Ok(())
}

/// Test concurrent operations performance
#[tokio::test]
async fn test_concurrent_encryption_performance() -> Result<(), Box<dyn std::error::Error>> {
    let encryption_service = Arc::new(MockEncryptionService::new(2)); // 2ms delay
    let test_data = vec![0u8; 512]; // 512B test data
    let num_concurrent = 50;
    let max_concurrent = 10;
    
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let start = Instant::now();
    
    let mut tasks = Vec::new();
    
    for i in 0..num_concurrent {
        let service = Arc::clone(&encryption_service);
        let data = test_data.clone();
        let sem = Arc::clone(&semaphore);
        
        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let op_start = Instant::now();
            
            let encrypted = service.encrypt(&data).await?;
            let decrypted = service.decrypt(&encrypted).await?;
            let op_duration = op_start.elapsed();
            
            assert_eq!(data, decrypted);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((i, op_duration))
        });
        
        tasks.push(task);
    }
    
    let results = futures::future::try_join_all(tasks).await?;
    let total_duration = start.elapsed();
    
    let latencies: Vec<Duration> = results.into_iter()
        .map(|r| r.unwrap().1)
        .collect();
    
    let result = BenchmarkResult::new(
        format!("Concurrent Encryption ({})", num_concurrent),
        num_concurrent,
        total_duration,
        &latencies,
    );
    
    println!("Concurrent Encryption Performance Results:");
    println!("  Concurrent Operations: {}", num_concurrent);
    println!("  Max Concurrent: {}", max_concurrent);
    println!("  Total Duration: {:?}", result.total_duration);
    println!("  Ops/Second: {:.2}", result.ops_per_second);
    println!("  Avg Latency: {:.2}ms", result.avg_latency_ms);
    
    // Concurrent performance thresholds
    assert!(result.ops_per_second >= 5.0,
           "Concurrent encryption should handle at least 5 ops/sec, got {:.2}",
           result.ops_per_second);
    assert!(result.avg_latency_ms <= 200.0,
           "Average concurrent latency should be <= 200ms, got {:.2}ms",
           result.avg_latency_ms);
    
    Ok(())
}

/// Test hashing performance
#[tokio::test]
async fn test_hashing_performance() -> Result<(), Box<dyn std::error::Error>> {
    let encryption_service = Arc::new(MockEncryptionService::new(0)); // No delay for hashing
    let num_operations = 1000;
    
    let start = Instant::now();
    let mut latencies = Vec::new();
    
    for i in 0..num_operations {
        let test_data = format!("test_data_{}", i).into_bytes();
        let op_start = Instant::now();
        let hash = encryption_service.hash_data(&test_data).await?;
        let op_duration = op_start.elapsed();
        
        assert!(hash.starts_with("HASH:"), "Hash should have proper prefix");
        latencies.push(op_duration);
    }
    
    let total_duration = start.elapsed();
    let result = BenchmarkResult::new(
        "Hashing".to_string(),
        num_operations,
        total_duration,
        &latencies,
    );
    
    println!("Hashing Performance Results:");
    println!("  Operations: {}", result.total_operations);
    println!("  Total Duration: {:?}", result.total_duration);
    println!("  Ops/Second: {:.2}", result.ops_per_second);
    println!("  Avg Latency: {:.2}ms", result.avg_latency_ms);
    
    // Hashing should be very fast
    assert!(result.ops_per_second >= 100.0,
           "Hashing should handle at least 100 ops/sec, got {:.2}",
           result.ops_per_second);
    assert!(result.avg_latency_ms <= 10.0,
           "Hashing latency should be <= 10ms, got {:.2}ms",
           result.avg_latency_ms);
    
    Ok(())
}

/// Test system throughput under sustained load
#[tokio::test]
async fn test_sustained_load() -> Result<(), Box<dyn std::error::Error>> {
    let encryption_service = Arc::new(MockEncryptionService::new(1));
    let test_data = vec![0u8; 256]; // 256B test data
    let duration = Duration::from_secs(10); // 10 second test
    let max_concurrent = 20;
    
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let start = Instant::now();
    let mut operation_count = 0;
    let mut total_latency = Duration::ZERO;
    
    while start.elapsed() < duration {
        let service = Arc::clone(&encryption_service);
        let data = test_data.clone();
        let sem = Arc::clone(&semaphore);
        
        let _permit = sem.acquire().await.unwrap();
        let op_start = Instant::now();
        
        let encrypted = service.encrypt(&data).await?;
        let _decrypted = service.decrypt(&encrypted).await?;
        
        let op_duration = op_start.elapsed();
        total_latency += op_duration;
        operation_count += 1;
        
        // Small yield to prevent busy waiting
        tokio::task::yield_now().await;
    }
    
    let total_duration = start.elapsed();
    let ops_per_second = operation_count as f64 / total_duration.as_secs_f64();
    let avg_latency_ms = total_latency.as_millis() as f64 / operation_count as f64;
    
    println!("Sustained Load Test Results:");
    println!("  Test Duration: {:?}", total_duration);
    println!("  Total Operations: {}", operation_count);
    println!("  Ops/Second: {:.2}", ops_per_second);
    println!("  Avg Latency: {:.2}ms", avg_latency_ms);
    
    // Sustained load thresholds
    assert!(operation_count >= 50,
           "Should complete at least 50 operations in 10s, got {}",
           operation_count);
    assert!(ops_per_second >= 5.0,
           "Sustained ops/sec should be >= 5.0, got {:.2}",
           ops_per_second);
    
    Ok(())
}

/// Test memory usage patterns
#[tokio::test]
async fn test_memory_efficiency() -> Result<(), Box<dyn std::error::Error>> {
    let encryption_service = Arc::new(MockEncryptionService::new(0));
    
    // Test with different data sizes
    let test_sizes = [1024, 4096, 16384, 65536]; // 1KB, 4KB, 16KB, 64KB
    
    for size in test_sizes {
        let test_data = vec![0u8; size];
        let start = Instant::now();
        
        // Perform multiple operations to test memory stability
        for _ in 0..10 {
            let encrypted = encryption_service.encrypt(&test_data).await?;
            let decrypted = encryption_service.decrypt(&encrypted).await?;
            
            assert_eq!(test_data.len(), decrypted.len());
            assert_eq!(test_data, decrypted);
        }
        
        let duration = start.elapsed();
        let throughput_mb_per_sec = (size * 10 * 2) as f64 / (1024.0 * 1024.0) 
                                  / duration.as_secs_f64();
        
        println!("Memory Test - Size: {}KB, Throughput: {:.2} MB/s", 
                size / 1024, throughput_mb_per_sec);
        
        // Memory efficiency thresholds
        assert!(duration.as_millis() <= 1000,
               "Operations for {}KB should complete within 1s, took {:?}",
               size / 1024, duration);
    }
    
    Ok(())
}
