//! Tun Server - Tunnel server component.
//!
//! Runs on a public VPS to accept tunnel connections and proxy traffic.

mod config;
mod db;
mod metrics;
mod multiplex;
mod proxy;
mod ratelimit;
mod tls;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use config::ServerConfig;
use db::{DbConfig, TunnelDb};
use ratelimit::{create_shared_limiter, RateLimitConfig};
use std::sync::Arc;
use tracing::{info, warn, Level};
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

    // Initialize database if configured
    let db = if let Some(ref database_url) = config.database_url {
        info!("Initializing database connection...");
        let db_config = DbConfig::new(database_url.clone(), config.get_server_id());
        match TunnelDb::new(&db_config).await {
            Ok(db) => {
                // Run migrations
                if let Err(e) = db.run_migrations().await {
                    warn!("Failed to run migrations (they may already be applied): {}", e);
                }
                Some(Arc::new(db))
            }
            Err(e) => {
                warn!("Failed to connect to database: {}. Running in memory-only mode.", e);
                None
            }
        }
    } else {
        info!("No database configured. Running in memory-only mode.");
        None
    };

    // Create shared rate limiter
    let rate_limit_config = RateLimitConfig::new(config.rate_limit_rps, config.rate_limit_burst);
    let rate_limiter = create_shared_limiter(&rate_limit_config);
    info!(
        "Rate limiting: {} req/s with burst of {}",
        config.rate_limit_rps, config.rate_limit_burst
    );

    // Create shared state
    let state = Arc::new(tunnel::TunnelRegistry::new(config.clone(), db.clone()));

    // Start servers based on mode
    let control_handle: tokio::task::JoinHandle<()>;
    let proxy_handle: tokio::task::JoinHandle<()>;
    
    if config.single_port {
        // Single-port mode: combine control and proxy
        info!("Running in single-port mode");
        let multiplex_state = state.clone();
        let multiplex_rate_limiter = rate_limiter.clone();
        let multiplex_addr = format!("0.0.0.0:{}", config.http_port);
        
        let handle = tokio::spawn(async move {
            if let Err(e) = multiplex::run_multiplexed_server(
                &multiplex_addr,
                multiplex_state,
                multiplex_rate_limiter,
            )
            .await
            {
                tracing::error!("Multiplexed server error: {}", e);
            }
        });
        
        // In single-port mode, we use the same handle for both
        control_handle = handle;
        proxy_handle = tokio::spawn(async {}); // Dummy handle
    } else {
        // Dual-port mode: separate control and proxy
        
        // Start the control server (for tunnel client connections)
        let control_state = state.clone();
        let control_rate_limiter = rate_limiter.clone();
        let control_addr = format!("0.0.0.0:{}", config.control_port);
        control_handle = tokio::spawn(async move {
            if let Err(e) =
                tunnel::run_control_server(&control_addr, control_state, control_rate_limiter).await
            {
                tracing::error!("Control server error: {}", e);
            }
        });

        // Start the HTTP proxy server (for public traffic)
        let proxy_state = state.clone();
        let proxy_rate_limiter = rate_limiter.clone();
        let http_addr = format!("0.0.0.0:{}", config.http_port);
        proxy_handle = tokio::spawn(async move {
            if let Err(e) = proxy::run_proxy_server(&http_addr, proxy_state, proxy_rate_limiter).await {
                tracing::error!("Proxy server error: {}", e);
            }
        });
    }

    // Start the metrics server if configured
    let metrics_handle = if let Some(metrics_port) = config.metrics_port {
        match metrics::TunnelMetrics::new() {
            Ok(tunnel_metrics) => {
                let metrics = Arc::new(tunnel_metrics);
                metrics::record_server_start();
                
                Some(tokio::spawn(async move {
                    if let Err(e) = metrics::run_metrics_server(metrics_port, metrics).await {
                        tracing::error!("Metrics server error: {}", e);
                    }
                }))
            }
            Err(e) => {
                warn!("Failed to initialize metrics: {}", e);
                None
            }
        }
    } else {
        info!("Metrics endpoint disabled (set TUN_METRICS_PORT to enable)");
        None
    };

    info!("Server is ready to accept connections");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    // Graceful shutdown: mark all tunnels as disconnected in database
    if let Some(ref db) = db {
        info!("Cleaning up database state...");
        if let Err(e) = db.disconnect_all_server_tunnels().await {
            warn!("Failed to cleanup database: {}", e);
        }
    }

    // Cleanup
    control_handle.abort();
    proxy_handle.abort();
    if let Some(handle) = metrics_handle {
        handle.abort();
    }

    Ok(())
}

