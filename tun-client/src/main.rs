//! Tun Client - Tunnel client component.
//!
//! Runs on local machine to expose local ports through the tunnel server.

mod config;
mod health;
mod pool;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use config::ClientConfig;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse configuration
    let config = ClientConfig::parse();

    // Initialize logging
    let _ = FmtSubscriber::builder()
        .with_max_level(if config.debug {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .with_target(false)
        .init();

    info!("Starting tun-client v{}", env!("CARGO_PKG_VERSION"));
    info!("Server: {}", config.server);
    
    // Log port mappings
    let port_mappings = config.get_port_mappings();
    if port_mappings.is_empty() {
        info!("Warning: No local ports configured. Use --local-port or --ports");
    } else if port_mappings.len() == 1 {
        info!("Local port: {}", port_mappings[0].port);
    } else {
        for mapping in &port_mappings {
            match &mapping.path_prefix {
                Some(prefix) => info!("  {} -> {}", prefix, mapping.port),
                None => info!("  (default) -> {}", mapping.port),
            }
        }
    }

    // Verify upstream connectivity if requested
    if config.verify_upstream {
        for mapping in &port_mappings {
            let addr = format!("127.0.0.1:{}", mapping.port);
            match health::verify_upstream(&addr, 5).await {
                Ok(latency) => info!("  ✓ Port {} is reachable ({:?})", mapping.port, latency),
                Err(e) => {
                    warn!("  ✗ Port {} is not reachable: {}", mapping.port, e);
                    if config.require_upstream {
                        return Err(anyhow::anyhow!(
                            "Upstream service on port {} is not reachable. \
                             Start the local service first or use --no-verify-upstream",
                            mapping.port
                        ));
                    }
                }
            }
        }
    }

    // Run the tunnel with auto-reconnect
    tunnel::run_tunnel_loop(&config).await
}

