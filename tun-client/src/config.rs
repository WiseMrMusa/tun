//! Client configuration.

use clap::Parser;

/// Tun Client - Securely expose local ports to the internet.
#[derive(Parser, Debug, Clone)]
#[command(name = "tun-client")]
#[command(author, version, about, long_about = None)]
pub struct ClientConfig {
    /// Tunnel server address (host:port or wss://host:port)
    #[arg(short, long, env = "TUN_SERVER", default_value = "localhost:8080")]
    pub server: String,

    /// Local port to expose
    #[arg(short = 'p', long, env = "TUN_LOCAL_PORT")]
    pub local_port: u16,

    /// Local host to forward to
    #[arg(short = 'H', long, env = "TUN_LOCAL_HOST", default_value = "127.0.0.1")]
    pub local_host: String,

    /// Authentication token
    #[arg(short, long, env = "TUN_TOKEN")]
    pub token: String,

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

    /// Enable debug logging
    #[arg(long, env = "TUN_DEBUG")]
    pub debug: bool,
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

    /// Get the local address to forward traffic to.
    pub fn local_addr(&self) -> String {
        format!("{}:{}", self.local_host, self.local_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_url() {
        let config = ClientConfig {
            server: "localhost:8080".to_string(),
            local_port: 3000,
            local_host: "127.0.0.1".to_string(),
            token: "test".to_string(),
            tls: false,
            insecure: false,
            reconnect_delay: 5,
            max_reconnects: 0,
            debug: false,
        };

        assert_eq!(config.ws_url(), "ws://localhost:8080/ws");

        let config_tls = ClientConfig {
            tls: true,
            ..config.clone()
        };
        assert_eq!(config_tls.ws_url(), "wss://localhost:8080/ws");
    }
}

