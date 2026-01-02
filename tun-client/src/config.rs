//! Client configuration.

use clap::Parser;

/// A port mapping configuration.
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// The local port to forward to
    pub port: u16,
    /// Optional path prefix (e.g., "/api" routes to this port)
    pub path_prefix: Option<String>,
}

impl std::str::FromStr for PortMapping {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Format: "port" or "port:/path"
        if let Some((port_str, path)) = s.split_once(':') {
            let port = port_str.parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", port_str))?;
            let path_prefix = if path.is_empty() { None } else { Some(path.to_string()) };
            Ok(PortMapping { port, path_prefix })
        } else {
            let port = s.parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", s))?;
            Ok(PortMapping { port, path_prefix: None })
        }
    }
}

/// Tun Client - Securely expose local ports to the internet.
#[derive(Parser, Debug, Clone)]
#[command(name = "tun-client")]
#[command(author, version, about, long_about = None)]
pub struct ClientConfig {
    /// Tunnel server address (host:port or wss://host:port)
    #[arg(short, long, env = "TUN_SERVER", default_value = "localhost:8080")]
    pub server: String,

    /// Local port to expose (deprecated: use --ports instead)
    #[arg(short = 'p', long, env = "TUN_LOCAL_PORT")]
    pub local_port: Option<u16>,

    /// Local ports to expose with optional path prefixes.
    /// Format: PORT or PORT:/path
    /// Examples: --ports 3000 --ports 3001:/api --ports 3002:/ws
    #[arg(long, value_parser = parse_port_mapping)]
    pub ports: Vec<PortMapping>,

    /// Local host to forward to
    #[arg(short = 'H', long, env = "TUN_LOCAL_HOST", default_value = "127.0.0.1")]
    pub local_host: String,

    /// Authentication token
    #[arg(short, long, env = "TUN_TOKEN")]
    pub token: String,

    /// Request a specific subdomain (if available)
    #[arg(long, env = "TUN_SUBDOMAIN")]
    pub subdomain: Option<String>,

    /// Enable TLS for server connection
    #[arg(long, env = "TUN_TLS")]
    pub tls: bool,

    /// Skip TLS certificate verification (insecure, for development only)
    #[arg(long, env = "TUN_INSECURE")]
    pub insecure: bool,

    /// Reconnect delay in seconds
    #[arg(long, env = "TUN_RECONNECT_DELAY", default_value = "5")]
    pub reconnect_delay: u64,

    /// Maximum reconnect attempts (0 = infinite)
    #[arg(long, env = "TUN_MAX_RECONNECTS", default_value = "0")]
    pub max_reconnects: u32,

    /// Verify upstream connectivity before establishing tunnel
    #[arg(long, env = "TUN_VERIFY_UPSTREAM", default_value = "true")]
    pub verify_upstream: bool,

    /// Require upstream to be reachable (exit if not)
    #[arg(long, env = "TUN_REQUIRE_UPSTREAM", default_value = "false")]
    pub require_upstream: bool,

    /// Enable periodic health checks (interval in seconds, 0 to disable)
    #[arg(long, env = "TUN_HEALTH_CHECK_INTERVAL", default_value = "0")]
    pub health_check_interval: u64,

    /// Enable debug logging
    #[arg(long, env = "TUN_DEBUG")]
    pub debug: bool,
}

fn parse_port_mapping(s: &str) -> Result<PortMapping, String> {
    s.parse()
}

impl ClientConfig {
    /// Get the WebSocket URL for the tunnel server.
    pub fn ws_url(&self) -> String {
        let server = &self.server;

        // If already a URL, return as-is
        if server.starts_with("ws://") || server.starts_with("wss://") {
            return format!("{}/ws", server.trim_end_matches('/'));
        }

        // Build URL from host:port
        let scheme = if self.tls { "wss" } else { "ws" };
        format!("{}://{}/ws", scheme, server)
    }

    /// Get all port mappings, including backward-compatible local_port.
    pub fn get_port_mappings(&self) -> Vec<PortMapping> {
        let mut mappings = self.ports.clone();
        
        // Add legacy local_port if specified and no --ports provided
        if let Some(port) = self.local_port {
            if mappings.is_empty() {
                mappings.push(PortMapping {
                    port,
                    path_prefix: None,
                });
            }
        }
        
        mappings
    }

    /// Get the default local port (first port or legacy local_port).
    pub fn default_port(&self) -> u16 {
        self.local_port
            .or_else(|| self.ports.first().map(|m| m.port))
            .unwrap_or(8080)
    }

    /// Get the local address to forward traffic to (using default port).
    pub fn local_addr(&self) -> String {
        format!("{}:{}", self.local_host, self.default_port())
    }

    /// Get the local address for a specific path.
    /// Routes based on path prefix if multiple ports are configured.
    pub fn local_addr_for_path(&self, path: &str) -> String {
        let mappings = self.get_port_mappings();
        
        // Find the best matching port mapping
        let port = mappings
            .iter()
            .filter(|m| m.path_prefix.is_some())
            .find(|m| {
                if let Some(prefix) = &m.path_prefix {
                    path.starts_with(prefix)
                } else {
                    false
                }
            })
            .map(|m| m.port)
            .unwrap_or_else(|| {
                // Fall back to the default port (first without prefix, or first overall)
                mappings
                    .iter()
                    .find(|m| m.path_prefix.is_none())
                    .or_else(|| mappings.first())
                    .map(|m| m.port)
                    .unwrap_or(8080)
            });
        
        format!("{}:{}", self.local_host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ClientConfig {
        ClientConfig {
            server: "localhost:8080".to_string(),
            local_port: Some(3000),
            ports: vec![],
            local_host: "127.0.0.1".to_string(),
            token: "test".to_string(),
            subdomain: None,
            tls: false,
            insecure: false,
            reconnect_delay: 5,
            max_reconnects: 0,
            verify_upstream: true,
            require_upstream: false,
            health_check_interval: 0,
            debug: false,
        }
    }

    #[test]
    fn test_ws_url() {
        let config = test_config();
        assert_eq!(config.ws_url(), "ws://localhost:8080/ws");

        let config_tls = ClientConfig {
            tls: true,
            ..config.clone()
        };
        assert_eq!(config_tls.ws_url(), "wss://localhost:8080/ws");
    }

    #[test]
    fn test_port_mapping_parse() {
        let simple: PortMapping = "3000".parse().unwrap();
        assert_eq!(simple.port, 3000);
        assert!(simple.path_prefix.is_none());

        let with_path: PortMapping = "3001:/api".parse().unwrap();
        assert_eq!(with_path.port, 3001);
        assert_eq!(with_path.path_prefix, Some("/api".to_string()));
    }

    #[test]
    fn test_local_addr_for_path() {
        let config = ClientConfig {
            ports: vec![
                PortMapping { port: 3000, path_prefix: None },
                PortMapping { port: 3001, path_prefix: Some("/api".to_string()) },
                PortMapping { port: 3002, path_prefix: Some("/ws".to_string()) },
            ],
            ..test_config()
        };

        // Default route goes to first port without prefix
        assert_eq!(config.local_addr_for_path("/"), "127.0.0.1:3000");
        assert_eq!(config.local_addr_for_path("/index.html"), "127.0.0.1:3000");

        // /api routes to port 3001
        assert_eq!(config.local_addr_for_path("/api"), "127.0.0.1:3001");
        assert_eq!(config.local_addr_for_path("/api/users"), "127.0.0.1:3001");

        // /ws routes to port 3002
        assert_eq!(config.local_addr_for_path("/ws"), "127.0.0.1:3002");
        assert_eq!(config.local_addr_for_path("/ws/events"), "127.0.0.1:3002");
    }
}

