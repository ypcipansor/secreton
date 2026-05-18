use secreton_core::metrics::{HealthCheckProvider, HealthMonitor, HealthStatus};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::sleep;

struct SlowCheck {
    name: String,
    delay: Duration,
}

impl HealthCheckProvider for SlowCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> Pin<Box<dyn Future<Output = (HealthStatus, Option<String>)> + Send + '_>> {
        let delay = self.delay;
        Box::pin(async move {
            sleep(delay).await;
            (HealthStatus::Healthy, None)
        })
    }
}

#[tokio::test]
async fn test_health_check_performance() {
    let mut monitor = HealthMonitor::new();
    let delay = Duration::from_millis(100);
    let count = 5;

    for i in 0..count {
        monitor.add_check(SlowCheck {
            name: format!("check-{}", i),
            delay,
        });
    }

    let start = std::time::Instant::now();
    let _results = monitor.check_all().await;
    let duration = start.elapsed();

    println!("Total duration: {:?}", duration);

    // Expectation for sequential: ~500ms
    // Expectation for concurrent: ~100ms
    assert!(
        duration.as_millis() < (delay.as_millis() * count as u128),
        "Should be concurrent"
    );

    // Allow for some overhead, but it should be much faster than sequential
    // 5 checks * 100ms = 500ms sequential
    // concurrent should be ~100ms + overhead
    assert!(
        duration.as_millis() < 300,
        "Should be significantly faster than sequential"
    );
}
