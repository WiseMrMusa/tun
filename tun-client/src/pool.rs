//! Connection pool for local service connections.
//!
//! Provides connection pooling to reduce the overhead of establishing new
//! TCP connections for each request to the local service.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

/// Configuration for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per host.
    pub max_connections: usize,
    /// Connection idle timeout.
    pub idle_timeout: Duration,
    /// Connection acquisition timeout.
    pub acquire_timeout: Duration,
    /// Maximum lifetime of a connection.
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 32,
            idle_timeout: Duration::from_secs(60),
            acquire_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(300),
        }
    }
}

/// A pooled connection.
pub struct PooledConnection {
    stream: Option<TcpStream>,
    host: String,
    created_at: Instant,
    last_used: Instant,
    pool: Arc<ConnectionPool>,
}

impl PooledConnection {
    /// Get a reference to the underlying stream.
    pub fn stream(&mut self) -> Option<&mut TcpStream> {
        self.stream.as_mut()
    }

    /// Take ownership of the stream (removes from pool).
    pub fn take(mut self) -> Option<TcpStream> {
        self.stream.take()
    }

    /// Check if the connection is still valid.
    pub fn is_valid(&self, config: &PoolConfig) -> bool {
        let now = Instant::now();
        let age = now.duration_since(self.created_at);
        let idle = now.duration_since(self.last_used);

        age < config.max_lifetime && idle < config.idle_timeout
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        // Return the connection to the pool if it's still valid
        if let Some(stream) = self.stream.take() {
            let pool = self.pool.clone();
            let host = self.host.clone();
            let created_at = self.created_at;
            let last_used = Instant::now();

            tokio::spawn(async move {
                pool.return_connection(host, stream, created_at, last_used)
                    .await;
            });
        }
    }
}

/// Entry in the connection pool.
struct PoolEntry {
    stream: TcpStream,
    created_at: Instant,
    last_used: Instant,
}

/// A connection pool for managing connections to local services.
pub struct ConnectionPool {
    config: PoolConfig,
    pools: Mutex<HashMap<String, Vec<PoolEntry>>>,
    active_connections: AtomicUsize,
    total_connections: AtomicUsize,
    reused_connections: AtomicUsize,
}

impl ConnectionPool {
    /// Create a new connection pool.
    pub fn new(config: PoolConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            pools: Mutex::new(HashMap::new()),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicUsize::new(0),
            reused_connections: AtomicUsize::new(0),
        })
    }

    /// Get a connection from the pool or create a new one.
    pub async fn get(self: &Arc<Self>, host: &str) -> Result<PooledConnection, std::io::Error> {
        // Try to get an existing connection
        if let Some(entry) = self.try_acquire(host).await {
            self.reused_connections.fetch_add(1, Ordering::Relaxed);
            debug!("Reusing pooled connection to {}", host);
            return Ok(PooledConnection {
                stream: Some(entry.stream),
                host: host.to_string(),
                created_at: entry.created_at,
                last_used: entry.last_used,
                pool: Arc::clone(self),
            });
        }

        // Create a new connection
        trace!("Creating new connection to {}", host);
        let stream = TcpStream::connect(host).await?;
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);

        Ok(PooledConnection {
            stream: Some(stream),
            host: host.to_string(),
            created_at: Instant::now(),
            last_used: Instant::now(),
            pool: Arc::clone(self),
        })
    }

    /// Try to acquire an existing connection from the pool.
    async fn try_acquire(&self, host: &str) -> Option<PoolEntry> {
        let mut pools = self.pools.lock().await;
        let pool = pools.get_mut(host)?;

        while let Some(entry) = pool.pop() {
            // Check if connection is still valid
            let now = Instant::now();
            let age = now.duration_since(entry.created_at);
            let idle = now.duration_since(entry.last_used);

            if age < self.config.max_lifetime && idle < self.config.idle_timeout {
                self.active_connections.fetch_add(1, Ordering::Relaxed);
                return Some(entry);
            }
            // Connection expired, drop it
            trace!(
                "Dropping expired connection to {} (age: {:?}, idle: {:?})",
                host,
                age,
                idle
            );
        }

        None
    }

    /// Return a connection to the pool.
    async fn return_connection(
        &self,
        host: String,
        stream: TcpStream,
        created_at: Instant,
        last_used: Instant,
    ) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);

        // Check if we should return to pool
        let now = Instant::now();
        let age = now.duration_since(created_at);

        if age >= self.config.max_lifetime {
            trace!("Not returning expired connection to pool for {}", host);
            return;
        }

        let mut pools = self.pools.lock().await;
        let pool = pools.entry(host.clone()).or_insert_with(Vec::new);

        // Check if pool is full
        if pool.len() >= self.config.max_connections {
            trace!("Pool is full for {}, dropping connection", host);
            return;
        }

        pool.push(PoolEntry {
            stream,
            created_at,
            last_used,
        });

        trace!(
            "Returned connection to pool for {} (pool size: {})",
            host,
            pool.len()
        );
    }

    /// Clean up expired connections.
    pub async fn cleanup(&self) {
        let mut pools = self.pools.lock().await;
        let now = Instant::now();
        let mut removed = 0;

        for (host, pool) in pools.iter_mut() {
            let before = pool.len();
            pool.retain(|entry| {
                let age = now.duration_since(entry.created_at);
                let idle = now.duration_since(entry.last_used);
                age < self.config.max_lifetime && idle < self.config.idle_timeout
            });
            removed += before - pool.len();
            if before != pool.len() {
                trace!(
                    "Cleaned up {} expired connections for {}",
                    before - pool.len(),
                    host
                );
            }
        }

        // Remove empty pools
        pools.retain(|_, v| !v.is_empty());

        if removed > 0 {
            debug!("Cleaned up {} expired connections", removed);
        }
    }

    /// Get pool statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            reused_connections: self.reused_connections.load(Ordering::Relaxed),
        }
    }

    /// Start a background cleanup task.
    pub fn start_cleanup_task(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                pool.cleanup().await;
            }
        })
    }
}

/// Statistics for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Currently active connections.
    pub active_connections: usize,
    /// Total connections created.
    pub total_connections: usize,
    /// Connections reused from pool.
    pub reused_connections: usize,
}

impl PoolStats {
    /// Calculate the reuse ratio.
    pub fn reuse_ratio(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            self.reused_connections as f64 / (self.total_connections + self.reused_connections) as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 32);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let stats = PoolStats {
            active_connections: 5,
            total_connections: 100,
            reused_connections: 200,
        };

        let ratio = stats.reuse_ratio();
        assert!(ratio > 0.6 && ratio < 0.7);
    }
}

