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

// ============================================================================
// HTTP/2 Connection Pool
// ============================================================================

/// Configuration for HTTP/2 connection pool.
#[derive(Debug, Clone)]
pub struct H2PoolConfig {
    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,
    /// Connection idle timeout.
    pub idle_timeout: Duration,
    /// Maximum lifetime of a connection.
    pub max_lifetime: Duration,
    /// Initial window size.
    pub initial_window_size: u32,
}

impl Default for H2PoolConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(300),
            initial_window_size: 65535,
        }
    }
}

/// State of an HTTP/2 connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ConnectionState {
    /// Connection is healthy and accepting new streams.
    Ready,
    /// Connection is busy (at max concurrent streams).
    Busy,
    /// Connection is draining (no new streams, waiting for existing to complete).
    Draining,
    /// Connection is closed.
    Closed,
}

/// An HTTP/2 connection in the pool.
pub struct H2Connection {
    /// Host this connection is for.
    host: String,
    /// When the connection was created.
    created_at: Instant,
    /// Last time a stream was opened.
    last_used: Instant,
    /// Current number of active streams.
    active_streams: AtomicUsize,
    /// Connection state.
    state: std::sync::atomic::AtomicU8,
    /// Configuration.
    config: H2PoolConfig,
}

impl H2Connection {
    /// Create a new H2 connection.
    pub fn new(host: &str, config: H2PoolConfig) -> Self {
        Self {
            host: host.to_string(),
            created_at: Instant::now(),
            last_used: Instant::now(),
            active_streams: AtomicUsize::new(0),
            state: std::sync::atomic::AtomicU8::new(H2ConnectionState::Ready as u8),
            config,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> H2ConnectionState {
        match self.state.load(Ordering::SeqCst) {
            0 => H2ConnectionState::Ready,
            1 => H2ConnectionState::Busy,
            2 => H2ConnectionState::Draining,
            _ => H2ConnectionState::Closed,
        }
    }

    /// Check if the connection can accept a new stream.
    pub fn can_accept_stream(&self) -> bool {
        let state = self.state();
        if state != H2ConnectionState::Ready && state != H2ConnectionState::Busy {
            return false;
        }

        let now = Instant::now();
        let age = now.duration_since(self.created_at);
        let idle = now.duration_since(self.last_used);

        if age >= self.config.max_lifetime || idle >= self.config.idle_timeout {
            return false;
        }

        let active = self.active_streams.load(Ordering::SeqCst);
        active < self.config.max_concurrent_streams as usize
    }

    /// Acquire a stream slot.
    pub fn acquire_stream(&self) -> bool {
        if !self.can_accept_stream() {
            return false;
        }

        let active = self.active_streams.fetch_add(1, Ordering::SeqCst) + 1;
        
        // Update state if at capacity
        if active >= self.config.max_concurrent_streams as usize {
            self.state.store(H2ConnectionState::Busy as u8, Ordering::SeqCst);
        }

        trace!(
            "Acquired H2 stream on {}, active: {}",
            self.host,
            active
        );
        true
    }

    /// Release a stream slot.
    pub fn release_stream(&self) {
        let active = self.active_streams.fetch_sub(1, Ordering::SeqCst) - 1;
        
        // Update state
        if active < self.config.max_concurrent_streams as usize {
            let current_state = self.state.load(Ordering::SeqCst);
            if current_state == H2ConnectionState::Busy as u8 {
                self.state.store(H2ConnectionState::Ready as u8, Ordering::SeqCst);
            }
        }

        trace!(
            "Released H2 stream on {}, active: {}",
            self.host,
            active
        );
    }

    /// Mark the connection as draining.
    pub fn drain(&self) {
        self.state.store(H2ConnectionState::Draining as u8, Ordering::SeqCst);
    }

    /// Mark the connection as closed.
    pub fn close(&self) {
        self.state.store(H2ConnectionState::Closed as u8, Ordering::SeqCst);
    }

    /// Get the host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the number of active streams.
    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::SeqCst)
    }

    /// Check if the connection is expired.
    pub fn is_expired(&self) -> bool {
        let now = Instant::now();
        let age = now.duration_since(self.created_at);
        age >= self.config.max_lifetime
    }

    /// Check if the connection is idle.
    pub fn is_idle(&self) -> bool {
        let now = Instant::now();
        let idle = now.duration_since(self.last_used);
        idle >= self.config.idle_timeout && self.active_streams() == 0
    }
}

/// HTTP/2 connection pool.
pub struct H2ConnectionPool {
    config: H2PoolConfig,
    connections: Mutex<HashMap<String, Vec<Arc<H2Connection>>>>,
    total_connections: AtomicUsize,
    total_streams: AtomicUsize,
    reused_streams: AtomicUsize,
}

impl H2ConnectionPool {
    /// Create a new HTTP/2 connection pool.
    pub fn new(config: H2PoolConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            connections: Mutex::new(HashMap::new()),
            total_connections: AtomicUsize::new(0),
            total_streams: AtomicUsize::new(0),
            reused_streams: AtomicUsize::new(0),
        })
    }

    /// Get a connection for a host, creating one if necessary.
    /// Returns the connection and whether it was newly created.
    pub async fn get_connection(&self, host: &str) -> (Arc<H2Connection>, bool) {
        let mut connections = self.connections.lock().await;
        let pool = connections.entry(host.to_string()).or_insert_with(Vec::new);

        // Try to find an existing connection that can accept a stream
        for conn in pool.iter() {
            if conn.can_accept_stream() && conn.acquire_stream() {
                self.reused_streams.fetch_add(1, Ordering::Relaxed);
                debug!("Reusing H2 connection to {}", host);
                return (Arc::clone(conn), false);
            }
        }

        // Create a new connection
        let conn = Arc::new(H2Connection::new(host, self.config.clone()));
        conn.acquire_stream();
        pool.push(Arc::clone(&conn));
        
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.total_streams.fetch_add(1, Ordering::Relaxed);
        info!("Created new H2 connection to {} (pool size: {})", host, pool.len());

        (conn, true)
    }

    /// Release a stream on a connection.
    pub fn release_stream(&self, conn: &H2Connection) {
        conn.release_stream();
    }

    /// Clean up expired connections.
    pub async fn cleanup(&self) {
        let mut connections = self.connections.lock().await;
        let mut removed = 0;

        for (host, pool) in connections.iter_mut() {
            let before = pool.len();
            pool.retain(|conn| {
                let should_keep = !conn.is_expired() && !conn.is_idle() && 
                                 conn.state() != H2ConnectionState::Closed;
                if !should_keep {
                    conn.close();
                }
                should_keep
            });
            removed += before - pool.len();
            if before != pool.len() {
                trace!("Cleaned up {} H2 connections for {}", before - pool.len(), host);
            }
        }

        connections.retain(|_, v| !v.is_empty());

        if removed > 0 {
            debug!("Cleaned up {} expired H2 connections", removed);
        }
    }

    /// Get pool statistics.
    pub fn stats(&self) -> H2PoolStats {
        H2PoolStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            total_streams: self.total_streams.load(Ordering::Relaxed),
            reused_streams: self.reused_streams.load(Ordering::Relaxed),
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

/// Statistics for the HTTP/2 connection pool.
#[derive(Debug, Clone)]
pub struct H2PoolStats {
    /// Total connections created.
    pub total_connections: usize,
    /// Total streams created.
    pub total_streams: usize,
    /// Streams reused from existing connections.
    pub reused_streams: usize,
}

impl H2PoolStats {
    /// Calculate the stream reuse ratio.
    pub fn reuse_ratio(&self) -> f64 {
        if self.total_streams == 0 {
            0.0
        } else {
            self.reused_streams as f64 / self.total_streams as f64
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

