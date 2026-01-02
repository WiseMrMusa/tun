//! Tun Server - Tunnel server component.
//!
//! Runs on a public VPS to accept tunnel connections and proxy traffic.

mod acl;
mod api;
mod cluster;
mod config;
mod dashboard;
mod db;
mod grpc;
mod hotreload;
mod ipfilter;
mod limits;
mod metrics;
mod multiplex;
mod proxy;
mod ratelimit;
mod shutdown;
mod sse;
mod tls;
mod tracing_otel;
mod transform;
mod tunnel;
mod validation;
mod websocket;

use acl::AclManager;
use anyhow::Result;
use api::ApiState;
use clap::Parser;
use config::ServerConfig;
use db::{DbConfig, TunnelDb};
use ipfilter::{IpFilter, IpFilterConfig};
use limits::{BodyLimitConfig, BodyLimiter};
use ratelimit::{create_shared_limiter, RateLimitConfig};
use shutdown::GracefulShutdown;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use transform::TransformConfig;
use validation::RequestValidator;

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

    // Start the API and dashboard server if configured
    let api_handle = if let Some(api_port) = config.api_port {
        let api_state = ApiState {
            registry: state.clone(),
            rate_limiter: rate_limiter.clone(),
            start_time: Instant::now(),
            api_key: config.api_key.clone(),
        };

        if config.api_key.is_some() {
            info!("API authentication enabled (admin endpoints require API key)");
        } else {
            warn!("API authentication disabled - admin endpoints are unprotected!");
        }

        let api_router = if config.enable_dashboard {
            info!("Dashboard enabled at http://0.0.0.0:{}/", api_port);
            api::create_api_router(api_state).merge(dashboard::dashboard_router())
        } else {
            api::create_api_router(api_state)
        };

        let api_addr = format!("0.0.0.0:{}", api_port);
        info!("API server listening on {}", api_addr);

        Some(tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(&api_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("Failed to bind API server: {}", e);
                    return;
                }
            };
            if let Err(e) = axum::serve(listener, api_router).await {
                tracing::error!("API server error: {}", e);
            }
        }))
    } else {
        if config.enable_dashboard {
            warn!("Dashboard enabled but TUN_API_PORT not set - dashboard will not be available");
        }
        info!("API server disabled (set TUN_API_PORT to enable)");
        None
    };

    info!("Server is ready to accept connections");

    // Setup graceful shutdown with configurable timeout
    let shutdown_timeout = config.shutdown_timeout.unwrap_or(shutdown::DEFAULT_SHUTDOWN_TIMEOUT_SECS);
    let graceful = GracefulShutdown::new(shutdown_timeout);
    let shutdown_signal = graceful.signal();

    // Wait for shutdown signal
    graceful.wait_for_signal().await;

    info!("Initiating graceful shutdown (timeout: {}s)...", shutdown_timeout);

    // Notify all tunnels of pending shutdown
    let tunnel_count = state.count();
    if tunnel_count > 0 {
        info!("Draining {} active tunnel(s)...", tunnel_count);
    }

    // Wait for connections to drain
    let drained = graceful.shutdown().await;
    if drained {
        info!("All connections drained successfully");
    } else {
        warn!("Shutdown timeout reached, forcing shutdown");
    }

    // Graceful shutdown: mark all tunnels as disconnected in database
    if let Some(ref db) = db {
        info!("Cleaning up database state...");
        if let Err(e) = db.disconnect_all_server_tunnels().await {
            warn!("Failed to cleanup database: {}", e);
        }
    }

    // Cleanup server tasks
    info!("Stopping server tasks...");
    control_handle.abort();
    proxy_handle.abort();
    if let Some(handle) = metrics_handle {
        handle.abort();
    }
    if let Some(handle) = api_handle {
        handle.abort();
    }

    // Drop the shutdown signal to clean up resources
    drop(shutdown_signal);

    info!("Shutdown complete");
    Ok(())
}

