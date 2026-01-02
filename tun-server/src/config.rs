//! Server configuration.

use clap::Parser;

/// Tun Server - Securely expose local ports to the internet.
#[derive(Parser, Debug, Clone)]
#[command(name = "tun-server")]
#[command(author, version, about, long_about = None)]
pub struct ServerConfig {
    /// Domain name for the tunnel server (e.g., tunnel.example.com)
    #[arg(long, env = "TUN_DOMAIN", default_value = "localhost")]
    pub domain: String,

    /// Port for tunnel client control connections (WebSocket)
    #[arg(long, env = "TUN_CONTROL_PORT", default_value = "8080")]
    pub control_port: u16,

    /// Port for public HTTP traffic
    #[arg(long, env = "TUN_HTTP_PORT", default_value = "8000")]
    pub http_port: u16,

    /// Path to TLS certificate file (PEM format)
    #[arg(long, env = "TUN_CERT_PATH")]
    pub cert_path: Option<String>,

    /// Path to TLS private key file (PEM format)
    #[arg(long, env = "TUN_KEY_PATH")]
    pub key_path: Option<String>,

    /// Authentication secret (hex-encoded, 32 bytes)
    /// If not provided, a random secret will be generated
    #[arg(long, env = "TUN_AUTH_SECRET")]
    pub auth_secret: Option<String>,

    /// Maximum number of concurrent tunnels
    #[arg(long, env = "TUN_MAX_TUNNELS", default_value = "100")]
    pub max_tunnels: usize,

    /// Request timeout in seconds
    #[arg(long, env = "TUN_REQUEST_TIMEOUT", default_value = "30")]
    pub request_timeout: u64,

    /// Enable debug logging
    #[arg(long, env = "TUN_DEBUG")]
    pub debug: bool,
}

impl ServerConfig {
    /// Get the base URL for tunnels.
    pub fn tunnel_base_url(&self, subdomain: &str) -> String {
        if self.cert_path.is_some() {
            format!("https://{}.{}", subdomain, self.domain)
        } else {
            format!("http://{}.{}:{}", subdomain, self.domain, self.http_port)
        }
    }
}

