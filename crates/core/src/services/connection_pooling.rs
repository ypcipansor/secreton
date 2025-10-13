// Database Connection Pooling - Efficient connection management
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("Pool error: {0}")]
    PoolError(String),
    #[error("Connection timeout: {0}")]
    Timeout(String),
    #[error("Pool exhausted: {0}")]
    Exhausted(String),
    #[error("Connection unhealthy: {0}")]
    Unhealthy(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, PoolError>;

/// Pool status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PoolStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    pub min_connections: usize,
    pub max_connections: usize,
    pub connection_timeout_ms: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
    pub health_check_interval_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 2,
            max_connections: 10,
            connection_timeout_ms: 5000,
            idle_timeout_secs: 600,      // 10 minutes
            max_lifetime_secs: 3600,     // 1 hour
            health_check_interval_secs: 30,
        }
    }
}

/// Pooled connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PooledConnection {
    pub id: String,
    pub backend: String,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub use_count: u64,
    pub is_healthy: bool,
    pub in_use: bool,
}

impl PooledConnection {
    pub fn new(backend: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            backend,
            created_at: Utc::now(),
            last_used: Utc::now(),
            use_count: 0,
            is_healthy: true,
            in_use: false,
        }
    }

    pub fn is_expired(&self, max_lifetime: Duration) -> bool {
        Utc::now() - self.created_at > max_lifetime
    }

    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        !self.in_use && (Utc::now() - self.last_used > idle_timeout)
    }
}

/// Pool metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMetrics {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub wait_time_ms: u64,
    pub acquisition_count: u64,
    pub acquisition_rate_per_sec: f64,
    pub last_updated: DateTime<Utc>,
}

impl PoolMetrics {
    pub fn new() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            idle_connections: 0,
            wait_time_ms: 0,
            acquisition_count: 0,
            acquisition_rate_per_sec: 0.0,
            last_updated: Utc::now(),
        }
    }
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection pool for a backend
#[derive(Debug, Clone)]
pub struct ConnectionPoolBackend {
    pub backend: String,
    pub config: PoolConfig,
    pub connections: Vec<PooledConnection>,
    pub metrics: PoolMetrics,
}

impl ConnectionPoolBackend {
    pub fn new(backend: String, config: PoolConfig) -> Self {
        Self {
            backend,
            config,
            connections: Vec::new(),
            metrics: PoolMetrics::new(),
        }
    }

    pub fn status(&self) -> PoolStatus {
        let healthy_count = self
            .connections
            .iter()
            .filter(|c| c.is_healthy)
            .count();

        let total = self.connections.len();

        if total == 0 || healthy_count == 0 {
            PoolStatus::Unhealthy
        } else if healthy_count < self.config.min_connections {
            PoolStatus::Degraded
        } else {
            PoolStatus::Healthy
        }
    }
}

/// Database connection pooling service
pub struct ConnectionPoolingService {
    pools: Arc<RwLock<HashMap<String, ConnectionPoolBackend>>>,
}

impl ConnectionPoolingService {
    pub fn new() -> Self {
        Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a connection pool for a backend
    pub async fn create_pool(&self, backend: String, config: PoolConfig) -> Result<()> {
        if config.min_connections > config.max_connections {
            return Err(PoolError::ConfigError(
                "min_connections cannot exceed max_connections".to_string(),
            ));
        }

        let mut pools = self.pools.write().await;

        let mut pool = ConnectionPoolBackend::new(backend.clone(), config.clone());

        // Initialize minimum connections
        for _ in 0..config.min_connections {
            let conn = PooledConnection::new(backend.clone());
            pool.connections.push(conn);
        }

        pool.metrics.total_connections = pool.connections.len();
        pool.metrics.idle_connections = pool.connections.len();

        pools.insert(backend, pool);

        Ok(())
    }

    /// Acquire a connection from the pool
    pub async fn acquire_connection(&self, backend: &str) -> Result<PooledConnection> {
        let mut pools = self.pools.write().await;
        let pool = pools
            .get_mut(backend)
            .ok_or_else(|| PoolError::PoolError(format!("Pool not found: {}", backend)))?;

        // Find an available healthy connection
        if let Some(conn) = pool
            .connections
            .iter_mut()
            .find(|c| !c.in_use && c.is_healthy)
        {
            conn.in_use = true;
            conn.last_used = Utc::now();
            conn.use_count += 1;

            // Update metrics
            pool.metrics.active_connections += 1;
            pool.metrics.idle_connections = pool.metrics.idle_connections.saturating_sub(1);
            pool.metrics.acquisition_count += 1;

            return Ok(conn.clone());
        }

        // No available connection, try to create new one if under max
        if pool.connections.len() < pool.config.max_connections {
            let mut conn = PooledConnection::new(backend.to_string());
            conn.in_use = true;
            conn.use_count = 1;

            pool.connections.push(conn.clone());

            // Update metrics
            pool.metrics.total_connections = pool.connections.len();
            pool.metrics.active_connections += 1;
            pool.metrics.acquisition_count += 1;

            return Ok(conn);
        }

        // Pool exhausted
        Err(PoolError::Exhausted(format!(
            "No available connections for {}",
            backend
        )))
    }

    /// Release a connection back to the pool
    pub async fn release_connection(&self, backend: &str, connection_id: &str) -> Result<()> {
        let mut pools = self.pools.write().await;
        let pool = pools
            .get_mut(backend)
            .ok_or_else(|| PoolError::PoolError(format!("Pool not found: {}", backend)))?;

        if let Some(conn) = pool.connections.iter_mut().find(|c| c.id == connection_id) {
            conn.in_use = false;
            conn.last_used = Utc::now();

            // Update metrics
            pool.metrics.active_connections = pool.metrics.active_connections.saturating_sub(1);
            pool.metrics.idle_connections += 1;

            Ok(())
        } else {
            Err(PoolError::PoolError("Connection not found".to_string()))
        }
    }

    /// Perform health check on connections
    pub async fn health_check(&self, backend: &str) -> Result<usize> {
        let mut pools = self.pools.write().await;
        let pool = pools
            .get_mut(backend)
            .ok_or_else(|| PoolError::PoolError(format!("Pool not found: {}", backend)))?;

        let mut unhealthy_count = 0;

        for conn in &mut pool.connections {
            // Mock health check
            if !self.check_connection_health(conn).await {
                conn.is_healthy = false;
                unhealthy_count += 1;
            }
        }

        Ok(unhealthy_count)
    }

    /// Check individual connection health
    async fn check_connection_health(&self, _conn: &PooledConnection) -> bool {
        // Mock health check
        // In real implementation, this would:
        // 1. Execute a simple query (SELECT 1)
        // 2. Verify response time
        // 3. Check connection state

        true
    }

    /// Evict idle connections
    pub async fn evict_idle(&self, backend: &str) -> Result<usize> {
        let mut pools = self.pools.write().await;
        let pool = pools
            .get_mut(backend)
            .ok_or_else(|| PoolError::PoolError(format!("Pool not found: {}", backend)))?;

        let idle_timeout = Duration::seconds(pool.config.idle_timeout_secs as i64);
        let max_lifetime = Duration::seconds(pool.config.max_lifetime_secs as i64);

        let initial_count = pool.connections.len();
        let min_connections = pool.config.min_connections;

        // Remove idle and expired connections, but keep minimum
        let mut current_count = initial_count;
        pool.connections.retain(|c| {
            if current_count <= min_connections {
                return true;
            }

            let should_keep = !c.is_idle(idle_timeout) && !c.is_expired(max_lifetime);
            if !should_keep {
                current_count -= 1;
            }
            should_keep
        });

        let evicted = initial_count - pool.connections.len();

        // Update metrics
        pool.metrics.total_connections = pool.connections.len();
        pool.metrics.idle_connections = pool
            .connections
            .iter()
            .filter(|c| !c.in_use)
            .count();

        Ok(evicted)
    }

    /// Resize pool dynamically
    pub async fn resize_pool(
        &self,
        backend: &str,
        new_max: usize,
        new_min: usize,
    ) -> Result<()> {
        if new_min > new_max {
            return Err(PoolError::ConfigError(
                "min cannot exceed max".to_string(),
            ));
        }

        let mut pools = self.pools.write().await;
        let pool = pools
            .get_mut(backend)
            .ok_or_else(|| PoolError::PoolError(format!("Pool not found: {}", backend)))?;

        pool.config.max_connections = new_max;
        pool.config.min_connections = new_min;

        // Add connections if below new minimum
        while pool.connections.len() < new_min {
            let conn = PooledConnection::new(backend.to_string());
            pool.connections.push(conn);
        }

        // Update metrics
        pool.metrics.total_connections = pool.connections.len();

        Ok(())
    }

    /// Get pool metrics
    pub async fn get_metrics(&self, backend: &str) -> Result<PoolMetrics> {
        let pools = self.pools.read().await;
        let pool = pools
            .get(backend)
            .ok_or_else(|| PoolError::PoolError(format!("Pool not found: {}", backend)))?;

        let mut metrics = pool.metrics.clone();
        metrics.last_updated = Utc::now();

        Ok(metrics)
    }

    /// Get pool status
    pub async fn get_status(&self, backend: &str) -> Result<PoolStatus> {
        let pools = self.pools.read().await;
        let pool = pools
            .get(backend)
            .ok_or_else(|| PoolError::PoolError(format!("Pool not found: {}", backend)))?;

        Ok(pool.status())
    }

    /// Drain pool (graceful shutdown)
    pub async fn drain_pool(&self, backend: &str) -> Result<()> {
        let mut pools = self.pools.write().await;
        pools.remove(backend);
        Ok(())
    }

    /// List all pools
    pub async fn list_pools(&self) -> Vec<String> {
        let pools = self.pools.read().await;
        pools.keys().cloned().collect()
    }
}

impl Default for ConnectionPoolingService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool() {
        let service = ConnectionPoolingService::new();
        let config = PoolConfig {
            min_connections: 3,
            max_connections: 10,
            ..Default::default()
        };

        service
            .create_pool("postgres-main".to_string(), config)
            .await
            .unwrap();

        let pools = service.list_pools().await;
        assert!(pools.contains(&"postgres-main".to_string()));

        let metrics = service.get_metrics("postgres-main").await.unwrap();
        assert_eq!(metrics.total_connections, 3);
        assert_eq!(metrics.idle_connections, 3);
    }

    #[tokio::test]
    async fn test_acquire_release() {
        let service = ConnectionPoolingService::new();
        let config = PoolConfig::default();

        service
            .create_pool("mysql-db".to_string(), config)
            .await
            .unwrap();

        // Acquire connection
        let conn = service.acquire_connection("mysql-db").await.unwrap();
        assert_eq!(conn.use_count, 1);

        let metrics = service.get_metrics("mysql-db").await.unwrap();
        assert_eq!(metrics.active_connections, 1);
        assert_eq!(metrics.idle_connections, 1); // min=2, one in use

        // Release connection
        service
            .release_connection("mysql-db", &conn.id)
            .await
            .unwrap();

        let metrics = service.get_metrics("mysql-db").await.unwrap();
        assert_eq!(metrics.active_connections, 0);
        assert_eq!(metrics.idle_connections, 2);
    }

    #[tokio::test]
    async fn test_health_check() {
        let service = ConnectionPoolingService::new();
        let config = PoolConfig::default();

        service
            .create_pool("cockroach-db".to_string(), config)
            .await
            .unwrap();

        let unhealthy = service.health_check("cockroach-db").await.unwrap();
        assert_eq!(unhealthy, 0); // All connections healthy in mock
    }

    #[tokio::test]
    async fn test_evict_idle() {
        let service = ConnectionPoolingService::new();
        let config = PoolConfig {
            min_connections: 2,
            max_connections: 10,
            idle_timeout_secs: 0, // Immediate eviction for testing
            ..Default::default()
        };

        service
            .create_pool("temp-db".to_string(), config)
            .await
            .unwrap();

        // Add extra connections and release them to make them idle
        let mut connection_ids = Vec::new();
        for _ in 0..3 {
            let conn = service.acquire_connection("temp-db").await.unwrap();
            connection_ids.push(conn.id);
        }

        // Release connections to make them idle
        for id in connection_ids {
            service.release_connection("temp-db", &id).await.unwrap();
        }

        let metrics_before = service.get_metrics("temp-db").await.unwrap();
        assert!(metrics_before.total_connections >= 2);

        // Evict idle (but will keep minimum)
        let evicted = service.evict_idle("temp-db").await.unwrap();

        let metrics_after = service.get_metrics("temp-db").await.unwrap();
        assert_eq!(metrics_after.total_connections, 2); // Kept minimum
    }

    #[tokio::test]
    async fn test_resize_pool() {
        let service = ConnectionPoolingService::new();
        let config = PoolConfig {
            min_connections: 2,
            max_connections: 5,
            ..Default::default()
        };

        service
            .create_pool("scalable-db".to_string(), config)
            .await
            .unwrap();

        // Resize to larger
        service
            .resize_pool("scalable-db", 20, 5)
            .await
            .unwrap();

        let metrics = service.get_metrics("scalable-db").await.unwrap();
        assert_eq!(metrics.total_connections, 5); // Increased to new min
    }

    #[tokio::test]
    async fn test_pool_exhaustion() {
        let service = ConnectionPoolingService::new();
        let config = PoolConfig {
            min_connections: 1,
            max_connections: 2,
            ..Default::default()
        };

        service
            .create_pool("limited-db".to_string(), config)
            .await
            .unwrap();

        // Acquire all connections
        let _conn1 = service.acquire_connection("limited-db").await.unwrap();
        let _conn2 = service.acquire_connection("limited-db").await.unwrap();

        // Try to acquire one more (should fail)
        let result = service.acquire_connection("limited-db").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PoolError::Exhausted(_)));
    }
}
