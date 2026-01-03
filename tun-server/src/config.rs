//! Server configuration.

use clap::Parser;

/// Default body size limit: 100MB
pub const DEFAULT_BODY_SIZE_LIMIT: usize = 100 * 1024 * 1024;

/// Default streaming threshold: 1MB
/// Bodies larger than this will be streamed instead of buffered
pub const DEFAULT_STREAMING_THRESHOLD: usize = 1024 * 1024;

/// Default stream chunk size: 64KB
pub const DEFAULT_STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Default authentication timeout: 10 seconds
pub const DEFAULT_AUTH_TIMEOUT: u64 = 10;

/// Default request timeout: 30 seconds
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// Default rate limit: requests per second per IP
pub const DEFAULT_RATE_LIMIT_RPS: u32 = 100;

/// Default rate limit burst size
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 200;

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

    /// Token time-to-live in seconds (default: 7 days)
    #[arg(long, env = "TUN_TOKEN_TTL", default_value = "604800")]
    pub token_ttl: u64,

    /// Maximum request body size in bytes (default: 100MB)
    #[arg(long, env = "TUN_BODY_SIZE_LIMIT", default_value = "104857600")]
    pub body_size_limit: usize,

    /// Streaming threshold in bytes (default: 1MB)
    /// Bodies larger than this will be streamed in chunks instead of buffered
    #[arg(long, env = "TUN_STREAMING_THRESHOLD", default_value = "1048576")]
    pub streaming_threshold: usize,

    /// Stream chunk size in bytes (default: 64KB)
    #[arg(long, env = "TUN_STREAM_CHUNK_SIZE", default_value = "65536")]
    pub stream_chunk_size: usize,

    /// Authentication timeout in seconds
    #[arg(long, env = "TUN_AUTH_TIMEOUT", default_value = "10")]
    pub auth_timeout: u64,

    /// Rate limit: requests per second per IP
    #[arg(long, env = "TUN_RATE_LIMIT_RPS", default_value = "100")]
    pub rate_limit_rps: u32,

    /// Rate limit burst size
    #[arg(long, env = "TUN_RATE_LIMIT_BURST", default_value = "200")]
    pub rate_limit_burst: u32,

    /// PostgreSQL database URL for persistence (optional)
    /// If not provided, tunnel state is stored in memory only
    #[arg(long, env = "TUN_DATABASE_URL")]
    pub database_url: Option<String>,

    /// Server ID for horizontal scaling (auto-generated if not provided)
    #[arg(long, env = "TUN_SERVER_ID")]
    pub server_id: Option<String>,

    /// Enable TLS on the HTTP proxy port (requires cert-path and key-path)
    #[arg(long, env = "TUN_PROXY_TLS")]
    pub proxy_tls: bool,

    /// Enable TLS on the control plane (WebSocket) port (requires cert-path and key-path)
    #[arg(long, env = "TUN_CONTROL_TLS")]
    pub control_tls: bool,

    /// Port for Prometheus metrics endpoint (disabled if not set)
    #[arg(long, env = "TUN_METRICS_PORT")]
    pub metrics_port: Option<u16>,

    /// Enable single-port mode (control and proxy on same port)
    /// When enabled, /ws routes to control plane, all other paths to proxy
    #[arg(long, env = "TUN_SINGLE_PORT")]
    pub single_port: bool,

    /// Enable debug logging
    #[arg(long, env = "TUN_DEBUG")]
    pub debug: bool,

    /// Path to IP allowlist file (one IP/CIDR per line)
    #[arg(long, env = "TUN_IP_ALLOWLIST")]
    pub ip_allowlist_file: Option<String>,

    /// Path to IP blocklist file (one IP/CIDR per line)
    #[arg(long, env = "TUN_IP_BLOCKLIST")]
    pub ip_blocklist_file: Option<String>,

    /// Graceful shutdown timeout in seconds
    /// If not set, uses default of 30 seconds
    #[arg(long, env = "TUN_SHUTDOWN_TIMEOUT")]
    pub shutdown_timeout: Option<u64>,

    /// Port for the introspection API server
    #[arg(long, env = "TUN_API_PORT")]
    pub api_port: Option<u16>,

    /// Enable the built-in WebUI dashboard
    #[arg(long, env = "TUN_ENABLE_DASHBOARD")]
    pub enable_dashboard: bool,

    /// API authentication key (required for admin endpoints)
    #[arg(long, env = "TUN_API_KEY")]
    pub api_key: Option<String>,

    /// Enable strict request validation (XSS, SQL injection detection)
    #[arg(long, env = "TUN_STRICT_VALIDATION")]
    pub strict_validation: bool,

    /// OTLP endpoint for distributed tracing (e.g., http://localhost:4317)
    #[arg(long, env = "TUN_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// OTLP API key for authenticated endpoints
    #[arg(long, env = "TUN_OTLP_API_KEY")]
    pub otlp_api_key: Option<String>,

    /// Path to per-subdomain ACL configuration file (YAML)
    #[arg(long, env = "TUN_ACL_CONFIG_FILE")]
    pub acl_config_file: Option<String>,

    /// Hot reload interval for config files (in seconds, 0 to disable)
    #[arg(long, env = "TUN_HOT_RELOAD_INTERVAL", default_value = "0")]
    pub hot_reload_interval: u64,

    /// Internal address for cluster communication
    #[arg(long, env = "TUN_CLUSTER_INTERNAL_ADDR")]
    pub cluster_internal_addr: Option<String>,

    /// Trusted proxy IP addresses or CIDR ranges (comma-separated).
    /// X-Forwarded-For and X-Real-IP headers are only trusted from these IPs.
    /// If not set, headers are always trusted (insecure, but compatible).
    #[arg(long, env = "TUN_TRUSTED_PROXIES", value_delimiter = ',')]
    pub trusted_proxies: Option<Vec<String>>,
}

impl ServerConfig {
    /// Get the base URL for tunnels.
    pub fn tunnel_base_url(&self, subdomain: &str) -> String {
        if self.cert_path.is_some() || self.proxy_tls {
            format!("https://{}.{}", subdomain, self.domain)
        } else {
            format!("http://{}.{}:{}", subdomain, self.domain, self.http_port)
        }
    }

    /// Get or generate the server ID.
    pub fn get_server_id(&self) -> String {
        self.server_id.clone().unwrap_or_else(|| {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            
            let mut hasher = DefaultHasher::new();
            hostname.hash(&mut hasher);
            std::process::id().hash(&mut hasher);
            format!("srv-{:016x}", hasher.finish())
        })
    }
}

