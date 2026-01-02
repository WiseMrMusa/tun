//! Tun Server - Tunnel server component.
//!
//! Runs on a public VPS to accept tunnel connections and proxy traffic.

mod config;
mod proxy;
mod tls;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use config::ServerConfig;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse configuration
    let config = ServerConfig::parse();

    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(if config.debug {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("Starting tun-server v{}", env!("CARGO_PKG_VERSION"));
    info!("Domain: {}", config.domain);
    info!("Control port: {}", config.control_port);
    info!("HTTP port: {}", config.http_port);

    // Create shared state
    let state = Arc::new(tunnel::TunnelRegistry::new(config.clone()));

    // Start the control server (for tunnel client connections)
    let control_state = state.clone();
    let control_addr = format!("0.0.0.0:{}", config.control_port);
    let control_handle = tokio::spawn(async move {
        if let Err(e) = tunnel::run_control_server(&control_addr, control_state).await {
            tracing::error!("Control server error: {}", e);
        }
    });

    // Start the HTTP proxy server (for public traffic)
    let proxy_state = state.clone();
    let http_addr = format!("0.0.0.0:{}", config.http_port);
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy::run_proxy_server(&http_addr, proxy_state).await {
            tracing::error!("Proxy server error: {}", e);
        }
    });

    info!("Server is ready to accept connections");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    // Cleanup
    control_handle.abort();
    proxy_handle.abort();

    Ok(())
}

