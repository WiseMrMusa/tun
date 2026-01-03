//! Cluster support for horizontal scaling.
//!
//! Allows multiple tunnel servers to work together by routing requests
//! to the appropriate server when a tunnel is connected elsewhere.

use crate::db::TunnelDb;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Information about a peer server in the cluster.
#[derive(Debug, Clone)]
pub struct PeerServer {
    /// Unique identifier for this server.
    pub id: String,
    /// Address to reach this server (for internal routing).
    pub internal_addr: String,
    /// When this peer was last seen.
    pub last_seen: Instant,
    /// Whether this peer is considered healthy.
    pub healthy: bool,
    /// Number of active tunnels on this peer.
    pub tunnel_count: usize,
}

impl PeerServer {
    /// Create a new peer server entry.
    pub fn new(id: &str, internal_addr: &str) -> Self {
        Self {
            id: id.to_string(),
            internal_addr: internal_addr.to_string(),
            last_seen: Instant::now(),
            healthy: true,
            tunnel_count: 0,
        }
    }

    /// Update the last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if the peer is stale.
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

/// Tunnel location in the cluster.
#[derive(Debug, Clone)]
pub struct TunnelLocation {
    /// Server ID where the tunnel is connected.
    pub server_id: String,
    /// Internal address of that server.
    pub server_addr: String,
    /// When this location was last updated.
    pub updated_at: Instant,
}

/// Cluster coordinator for managing multiple tunnel servers.
pub struct ClusterCoordinator {
    /// This server's unique identifier.
    pub server_id: String,
    /// This server's internal address.
    pub internal_addr: String,
    /// Known peer servers.
    peers: DashMap<String, PeerServer>,
    /// Tunnel location cache.
    tunnel_locations: DashMap<String, TunnelLocation>,
    /// Stale timeout for peers.
    peer_timeout: Duration,
    /// Cache TTL for tunnel locations.
    location_cache_ttl: Duration,
}

impl ClusterCoordinator {
    /// Create a new cluster coordinator.
    pub fn new(server_id: &str, internal_addr: &str) -> Self {
        info!(
            "Initializing cluster coordinator for server '{}' at {}",
            server_id, internal_addr
        );
        Self {
            server_id: server_id.to_string(),
            internal_addr: internal_addr.to_string(),
            peers: DashMap::new(),
            tunnel_locations: DashMap::new(),
            peer_timeout: Duration::from_secs(30),
            location_cache_ttl: Duration::from_secs(10),
        }
    }

    /// Register or update a peer server.
    pub fn register_peer(&self, peer: PeerServer) {
        if peer.id == self.server_id {
            return; // Don't register self
        }

        debug!("Registering peer server: {} at {}", peer.id, peer.internal_addr);
        self.peers.insert(peer.id.clone(), peer);
    }

    /// Remove a peer server.
    pub fn remove_peer(&self, peer_id: &str) {
        self.peers.remove(peer_id);
        info!("Removed peer server: {}", peer_id);
    }

    /// Update peer with heartbeat.
    pub fn heartbeat_peer(&self, peer_id: &str) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.touch();
            peer.healthy = true;
        }
    }

    /// Mark a peer as unhealthy.
    pub fn mark_peer_unhealthy(&self, peer_id: &str) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.healthy = false;
            warn!("Marked peer {} as unhealthy", peer_id);
        }
    }

    /// Get a peer by ID.
    pub fn get_peer(&self, peer_id: &str) -> Option<PeerServer> {
        self.peers.get(peer_id).map(|r| r.clone())
    }

    /// Get all healthy peers.
    pub fn healthy_peers(&self) -> Vec<PeerServer> {
        self.peers
            .iter()
            .filter(|r| r.healthy && !r.is_stale(self.peer_timeout))
            .map(|r| r.clone())
            .collect()
    }

    /// Record a tunnel location.
    pub fn record_tunnel_location(&self, subdomain: &str, server_id: &str, server_addr: &str) {
        let location = TunnelLocation {
            server_id: server_id.to_string(),
            server_addr: server_addr.to_string(),
            updated_at: Instant::now(),
        };
        self.tunnel_locations.insert(subdomain.to_string(), location);
        debug!(
            "Recorded tunnel location: {} on server {}",
            subdomain, server_id
        );
    }

    /// Get the server where a tunnel is located.
    pub fn get_tunnel_location(&self, subdomain: &str) -> Option<TunnelLocation> {
        if let Some(location) = self.tunnel_locations.get(subdomain) {
            // Check if cache is still valid
            if location.updated_at.elapsed() < self.location_cache_ttl {
                return Some(location.clone());
            }
        }
        None
    }

    /// Check if a tunnel is on this server.
    pub fn is_local(&self, subdomain: &str) -> bool {
        if let Some(location) = self.get_tunnel_location(subdomain) {
            location.server_id == self.server_id
        } else {
            false
        }
    }

    /// Get the address to route a request to.
    /// Returns None if the tunnel is local or location is unknown.
    pub fn get_route_target(&self, subdomain: &str) -> Option<String> {
        if let Some(location) = self.get_tunnel_location(subdomain) {
            if location.server_id != self.server_id {
                // Need to route to another server
                return Some(location.server_addr);
            }
        }
        None
    }

    /// Clear stale tunnel locations.
    pub fn cleanup_locations(&self) {
        let now = Instant::now();
        let mut removed = 0;

        self.tunnel_locations.retain(|_, v| {
            let fresh = v.updated_at.elapsed() < self.location_cache_ttl * 2;
            if !fresh {
                removed += 1;
            }
            fresh
        });

        if removed > 0 {
            debug!("Cleaned up {} stale tunnel locations", removed);
        }
    }

    /// Cleanup stale peers.
    pub fn cleanup_peers(&self) {
        let mut removed = 0;

        self.peers.retain(|id, peer| {
            let fresh = !peer.is_stale(self.peer_timeout * 2);
            if !fresh {
                info!("Removing stale peer: {}", id);
                removed += 1;
            }
            fresh
        });

        if removed > 0 {
            debug!("Cleaned up {} stale peers", removed);
        }
    }

    /// Get cluster statistics.
    pub fn stats(&self) -> ClusterStats {
        let total_peers = self.peers.len();
        let healthy_peers = self
            .peers
            .iter()
            .filter(|r| r.healthy && !r.is_stale(self.peer_timeout))
            .count();
        let cached_locations = self.tunnel_locations.len();

        ClusterStats {
            server_id: self.server_id.clone(),
            total_peers,
            healthy_peers,
            cached_locations,
        }
    }
}

/// Cluster statistics.
#[derive(Debug, Clone)]
pub struct ClusterStats {
    /// This server's ID.
    pub server_id: String,
    /// Total known peers.
    pub total_peers: usize,
    /// Healthy peers.
    pub healthy_peers: usize,
    /// Cached tunnel locations.
    pub cached_locations: usize,
}

/// Database-backed cluster coordinator for horizontal scaling.
/// Uses PostgreSQL for peer discovery and tunnel location.
pub struct DbClusterCoordinator {
    /// This server's unique identifier.
    pub server_id: String,
    /// This server's internal address.
    pub internal_addr: String,
    /// Database connection.
    db: Arc<TunnelDb>,
    /// Local cache of tunnel locations.
    tunnel_cache: DashMap<String, TunnelLocation>,
    /// Cache TTL.
    cache_ttl: Duration,
    /// Peer heartbeat interval.
    heartbeat_interval: Duration,
    /// Stale peer threshold.
    stale_threshold: Duration,
}

impl DbClusterCoordinator {
    /// Create a new database-backed cluster coordinator.
    pub fn new(server_id: &str, internal_addr: &str, db: Arc<TunnelDb>) -> Self {
        info!(
            "Initializing DB cluster coordinator for server '{}' at {}",
            server_id, internal_addr
        );
        Self {
            server_id: server_id.to_string(),
            internal_addr: internal_addr.to_string(),
            db,
            tunnel_cache: DashMap::new(),
            cache_ttl: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(10),
            stale_threshold: Duration::from_secs(30),
        }
    }

    /// Register this server with the cluster.
    pub async fn register(&self, tunnel_count: i32) -> Result<(), String> {
        self.db
            .register_peer(&self.internal_addr, tunnel_count)
            .await
            .map_err(|e| format!("Failed to register peer: {}", e))
    }

    /// Deregister this server from the cluster.
    pub async fn deregister(&self) -> Result<(), String> {
        self.db
            .deregister_peer()
            .await
            .map_err(|e| format!("Failed to deregister peer: {}", e))
    }

    /// Find which server hosts a tunnel.
    pub async fn find_tunnel_server(&self, subdomain: &str) -> Option<String> {
        // Check local cache first
        if let Some(location) = self.tunnel_cache.get(subdomain) {
            if location.updated_at.elapsed() < self.cache_ttl {
                if location.server_id != self.server_id {
                    return Some(location.server_addr.clone());
                }
                return None; // Local
            }
        }

        // Query database
        match self.db.find_tunnel_server(subdomain).await {
            Ok(Some(peer)) => {
                // Update cache
                self.tunnel_cache.insert(
                    subdomain.to_string(),
                    TunnelLocation {
                        server_id: peer.server_id.clone(),
                        server_addr: peer.internal_addr.clone(),
                        updated_at: Instant::now(),
                    },
                );

                if peer.server_id != self.server_id {
                    Some(peer.internal_addr)
                } else {
                    None // Local
                }
            }
            Ok(None) => None,
            Err(e) => {
                warn!("Failed to find tunnel server for {}: {}", subdomain, e);
                None
            }
        }
    }

    /// Get healthy peers for load balancing.
    pub async fn get_healthy_peers(&self) -> Vec<crate::db::PeerRecord> {
        match self
            .db
            .get_healthy_peers(self.stale_threshold.as_secs() as i64)
            .await
        {
            Ok(peers) => peers,
            Err(e) => {
                warn!("Failed to get healthy peers: {}", e);
                Vec::new()
            }
        }
    }

    /// Start the background peer sync task.
    pub fn start_sync_task(
        self: &Arc<Self>,
        tunnel_count_fn: Arc<dyn Fn() -> i32 + Send + Sync>,
    ) -> tokio::task::JoinHandle<()> {
        let coordinator = Arc::clone(self);
        let heartbeat_interval = self.heartbeat_interval;
        let stale_threshold = self.stale_threshold;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(heartbeat_interval);
            
            loop {
                interval.tick().await;
                
                // Update our heartbeat with current tunnel count
                let tunnel_count = tunnel_count_fn();
                if let Err(e) = coordinator.register(tunnel_count).await {
                    error!("Failed to update peer heartbeat: {}", e);
                }
                
                // Cleanup stale peers periodically (every 3rd heartbeat)
                static CLEANUP_COUNTER: std::sync::atomic::AtomicU32 = 
                    std::sync::atomic::AtomicU32::new(0);
                let count = CLEANUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count % 3 == 0 {
                    if let Err(e) = coordinator.db.cleanup_stale_peers(stale_threshold.as_secs() as i64).await {
                        warn!("Failed to cleanup stale peers: {}", e);
                    }
                    
                    // Also cleanup local cache
                    coordinator.cleanup_cache();
                }
            }
        })
    }

    /// Cleanup stale cache entries.
    fn cleanup_cache(&self) {
        let ttl = self.cache_ttl * 2;
        self.tunnel_cache.retain(|_, v| v.updated_at.elapsed() < ttl);
    }

    /// Get cluster statistics.
    pub async fn stats(&self) -> DbClusterStats {
        let healthy_peers = self.get_healthy_peers().await;
        DbClusterStats {
            server_id: self.server_id.clone(),
            healthy_peer_count: healthy_peers.len(),
            cached_locations: self.tunnel_cache.len(),
        }
    }
}

/// Database cluster statistics.
#[derive(Debug, Clone)]
pub struct DbClusterStats {
    pub server_id: String,
    pub healthy_peer_count: usize,
    pub cached_locations: usize,
}

/// Route a request to another server in the cluster.
/// Uses proper HTTP parsing with Content-Length handling for full response body.
pub async fn route_to_peer(
    peer_addr: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(peer_addr)
        .await
        .map_err(|e| format!("Failed to connect to peer {}: {}", peer_addr, e))?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Build HTTP request
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
    request.push_str(&format!("Host: {}\r\n", peer_addr));
    request.push_str("X-Forwarded-By: cluster\r\n");
    request.push_str("Connection: close\r\n");
    request.push_str(&format!("Content-Length: {}\r\n", body.len()));

    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("host")
            && !name.eq_ignore_ascii_case("content-length")
            && !name.eq_ignore_ascii_case("connection")
        {
            request.push_str(&format!("{}: {}\r\n", name, value));
        }
    }
    request.push_str("\r\n");

    // Send request
    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("Failed to write request: {}", e))?;
    writer
        .write_all(body)
        .await
        .map_err(|e| format!("Failed to write body: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush: {}", e))?;

    // Read status line
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .map_err(|e| format!("Failed to read status line: {}", e))?;

    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("Invalid status line: {}", status_line))?;

    // Read headers
    let mut response_headers = Vec::new();
    let mut content_length: Option<usize> = None;

    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("Failed to read header: {}", e))?;

        let line = line.trim_end_matches(&['\r', '\n'][..]);
        if line.is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(": ") {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().ok();
            }
            response_headers.push((name.to_string(), value.to_string()));
        }
    }

    // Read body based on Content-Length or until EOF
    let response_body = if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        reader
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("Failed to read body: {}", e))?;
        body
    } else {
        // No Content-Length - read until EOF (connection close)
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .await
            .map_err(|e| format!("Failed to read body: {}", e))?;
        body
    };

    Ok((status, response_headers, response_body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_server() {
        let peer = PeerServer::new("server1", "192.168.1.1:8080");
        assert!(peer.healthy);
        assert!(!peer.is_stale(Duration::from_secs(10)));
    }

    #[test]
    fn test_cluster_coordinator() {
        let coord = ClusterCoordinator::new("server1", "192.168.1.1:8080");

        // Register a peer
        let peer = PeerServer::new("server2", "192.168.1.2:8080");
        coord.register_peer(peer);

        assert_eq!(coord.peers.len(), 1);
        assert!(coord.get_peer("server2").is_some());

        // Record tunnel location
        coord.record_tunnel_location("test", "server2", "192.168.1.2:8080");
        assert!(!coord.is_local("test"));
        assert_eq!(
            coord.get_route_target("test"),
            Some("192.168.1.2:8080".to_string())
        );
    }
}

