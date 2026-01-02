//! Tun Server - Tunnel server component.
//!
//! Runs on a public VPS to accept tunnel connections and proxy traffic.

mod acl;
mod api;
mod circuit_breaker;
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
use cluster::DbClusterCoordinator;
use config::ServerConfig;
use db::{DbConfig, TunnelDb};
use hotreload::{HotReloadConfig, HotReloadManager};
use ipfilter::{IpFilter, IpFilterConfig};
use ratelimit::{create_shared_limiter, RateLimitConfig};
use shutdown::GracefulShutdown;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_otel::OtlpConfig;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse configuration
    let config = ServerConfig::parse();

    // Initialize logging - use OTLP if configured, otherwise basic logging
    if let Some(ref otlp_endpoint) = config.otlp_endpoint {
        let otlp_config = OtlpConfig::new(otlp_endpoint, "tun-server")
            .with_sample_rate(1.0);
        let otlp_config = if let Some(ref api_key) = config.otlp_api_key {
            otlp_config.with_api_key(api_key)
        } else {
            otlp_config
        };

        if let Err(e) = tracing_otel::init_otel_tracing(&otlp_config) {
            eprintln!("Failed to initialize OTLP tracing: {}. Falling back to basic logging.", e);
            tracing_otel::init_basic_logging(config.debug);
        } else {
            info!("OpenTelemetry OTLP tracing enabled");
        }
    } else {
        tracing_otel::init_basic_logging(config.debug);
    }

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

    // Initialize IP filter
    let ip_filter_config = IpFilterConfig {
        allowlist_file: config.ip_allowlist_file.clone(),
        blocklist_file: config.ip_blocklist_file.clone(),
        allow_all_if_empty: true,
    };
    let ip_filter = Arc::new(RwLock::new(IpFilter::from_config(&ip_filter_config)));

    if config.ip_allowlist_file.is_some() || config.ip_blocklist_file.is_some() {
        info!("IP filtering enabled");
    }

    // Initialize ACL manager
    let acl_manager = Arc::new(RwLock::new(AclManager::new()));

    // Load ACL config if specified
    if let Some(ref acl_path) = config.acl_config_file {
        info!("Loading ACL configuration from {}", acl_path);
        // ACL loading is handled by hot reload
    }

    // Create shared rate limiter
    let rate_limit_config = RateLimitConfig::new(config.rate_limit_rps, config.rate_limit_burst);
    let rate_limiter = create_shared_limiter(&rate_limit_config);
    info!(
        "Rate limiting: {} req/s with burst of {}",
        config.rate_limit_rps, config.rate_limit_burst
    );

    // Create shared state
    let state = Arc::new(tunnel::TunnelRegistry::new(config.clone(), db.clone()));

    // === Initialize Cluster Coordinator ===
    let cluster_coordinator = if let Some(ref db) = db {
        let internal_addr = config.cluster_internal_addr.clone()
            .unwrap_or_else(|| format!("127.0.0.1:{}", config.http_port));
        
        let coord = Arc::new(DbClusterCoordinator::new(
            &config.get_server_id(),
            &internal_addr,
            db.clone(),
        ));

        // Start background sync task
        let tunnel_count_fn = {
            let state_clone = state.clone();
            Arc::new(move || state_clone.count() as i32)
        };
        coord.start_sync_task(tunnel_count_fn);
        
        info!("Cluster coordinator initialized (internal addr: {})", internal_addr);
        Some(coord)
    } else {
        info!("Cluster mode disabled (no database configured)");
        None
    };

    // === Start Background Cleanup Tasks ===
    
    // Rate limiter cleanup task (every 60 seconds, remove entries older than 5 minutes)
    let rate_limiter_cleanup = {
        let rate_limiter_clone = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rate_limiter_clone.cleanup(300); // 5 minute stale threshold
            }
        })
    };
    info!("Rate limiter cleanup task started (interval: 60s, max age: 300s)");

    // ACL manager cleanup task (every 120 seconds, remove entries older than 10 minutes)
    let acl_cleanup = {
        let acl_manager_clone = acl_manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(120));
            loop {
                interval.tick().await;
                let manager = acl_manager_clone.read().await;
                manager.cleanup(Duration::from_secs(600));
            }
        })
    };
    info!("ACL cleanup task started (interval: 120s, max age: 600s)");

    // === Initialize Hot Reload ===
    let hot_reload_handle = if config.hot_reload_interval > 0 {
        let mut watch_paths = Vec::new();
        
        if let Some(ref path) = config.ip_allowlist_file {
            watch_paths.push(PathBuf::from(path));
        }
        if let Some(ref path) = config.ip_blocklist_file {
            watch_paths.push(PathBuf::from(path));
        }
        if let Some(ref path) = config.acl_config_file {
            watch_paths.push(PathBuf::from(path));
        }

        if !watch_paths.is_empty() {
            let hot_reload_config = HotReloadConfig::new(watch_paths.clone())
                .debounce(Duration::from_secs(config.hot_reload_interval));

            let (manager, mut reload_rx) = HotReloadManager::new(
                hot_reload_config,
                ip_filter.clone(),
                acl_manager.clone(),
            );

            // Start file watcher
            match manager.start_watcher(
                config.ip_allowlist_file.clone().map(PathBuf::from),
                config.ip_blocklist_file.clone().map(PathBuf::from),
                config.acl_config_file.clone().map(PathBuf::from),
            ) {
                Ok(watcher_handle) => {
                    // Spawn task to log reload events
                    tokio::spawn(async move {
                        while let Some(event) = reload_rx.recv().await {
                            info!("Configuration reloaded: {:?}", event);
                        }
                    });
                    
                    info!("Hot reload enabled (watching {} files)", watch_paths.len());
                    Some(watcher_handle)
                }
                Err(e) => {
                    warn!("Failed to start hot reload watcher: {}", e);
                    None
                }
            }
        } else {
            info!("Hot reload disabled (no config files specified)");
            None
        }
    } else {
        info!("Hot reload disabled (interval: 0)");
        None
    };

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
            if let Err(e) =
                proxy::run_proxy_server(&http_addr, proxy_state, proxy_rate_limiter).await
            {
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
    let shutdown_timeout = config
        .shutdown_timeout
        .unwrap_or(shutdown::DEFAULT_SHUTDOWN_TIMEOUT_SECS);
    let graceful = GracefulShutdown::new(shutdown_timeout);
    let shutdown_signal = graceful.signal();

    // Wait for shutdown signal
    graceful.wait_for_signal().await;

    info!(
        "Initiating graceful shutdown (timeout: {}s)...",
        shutdown_timeout
    );

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

    // Deregister from cluster
    if let Some(ref coord) = cluster_coordinator {
        info!("Deregistering from cluster...");
        if let Err(e) = coord.deregister().await {
            warn!("Failed to deregister from cluster: {}", e);
        }
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
    if let Some(handle) = hot_reload_handle {
        handle.abort();
    }
    
    // Abort background cleanup tasks
    rate_limiter_cleanup.abort();
    acl_cleanup.abort();

    // Shutdown OpenTelemetry
    tracing_otel::shutdown_otel();

    // Drop the shutdown signal to clean up resources
    drop(shutdown_signal);

    info!("Shutdown complete");
    Ok(())
}
