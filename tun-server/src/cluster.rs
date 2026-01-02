//! Cluster support for horizontal scaling.
//!
//! Allows multiple tunnel servers to work together by routing requests
//! to the appropriate server when a tunnel is connected elsewhere.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use tun_core::protocol::TunnelId;

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

/// Route a request to another server in the cluster.
pub async fn route_to_peer(
    peer_addr: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(peer_addr)
        .await
        .map_err(|e| format!("Failed to connect to peer {}: {}", peer_addr, e))?;

    let (mut reader, mut writer) = stream.into_split();

    // Build HTTP request
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
    request.push_str(&format!("Host: {}\r\n", peer_addr));
    request.push_str("X-Forwarded-By: cluster\r\n");
    request.push_str(&format!("Content-Length: {}\r\n", body.len()));

    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("host")
            && !name.eq_ignore_ascii_case("content-length")
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

    // Read response
    let mut response = vec![0u8; 8192];
    let n = reader
        .read(&mut response)
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Parse response (simple parsing)
    let response_str = String::from_utf8_lossy(&response[..n]);
    let mut lines = response_str.lines();

    let status_line = lines.next().ok_or("Empty response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("Invalid status code")?;

    let mut response_headers = Vec::new();
    let mut body_start = 0;

    for (i, line) in lines.enumerate() {
        if line.is_empty() {
            body_start = i + 2; // Skip status line and headers
            break;
        }
        if let Some((name, value)) = line.split_once(": ") {
            response_headers.push((name.to_string(), value.to_string()));
        }
    }

    // Extract body (simplified)
    let response_body = response_str
        .lines()
        .skip(body_start)
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();

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

