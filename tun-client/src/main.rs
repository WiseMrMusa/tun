//! Tun Client - Tunnel client component.
//!
//! Runs on local machine to expose local ports through the tunnel server.

mod config;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use config::ClientConfig;
use tracing::{info, Level};
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

    // Run the tunnel with auto-reconnect
    tunnel::run_tunnel_loop(&config).await
}

