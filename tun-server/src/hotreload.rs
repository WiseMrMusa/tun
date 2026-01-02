//! Hot reload support for configuration files.
//!
//! Watches configuration files for changes and triggers reloads without server restart.

use crate::acl::AclManager;
use crate::ipfilter::IpFilter;
use crate::metrics;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Configuration for hot reload.
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// Files to watch.
    pub watch_paths: Vec<PathBuf>,
    /// Debounce interval to avoid rapid reloads.
    pub debounce_interval: Duration,
    /// Enable hot reload.
    pub enabled: bool,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            watch_paths: Vec::new(),
            debounce_interval: Duration::from_secs(2),
            enabled: false,
        }
    }
}

impl HotReloadConfig {
    /// Create a new hot reload config with the specified paths.
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            watch_paths: paths,
            debounce_interval: Duration::from_secs(2),
            enabled: true,
        }
    }

    /// Add a path to watch.
    pub fn watch_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.watch_paths.push(path.into());
        self
    }

    /// Set the debounce interval.
    pub fn debounce(mut self, interval: Duration) -> Self {
        self.debounce_interval = interval;
        self
    }
}

/// Reload event types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadEvent {
    /// IP allowlist/blocklist changed.
    IpFilter,
    /// ACL configuration changed.
    AclConfig,
    /// Per-subdomain config changed.
    SubdomainConfig,
    /// Unknown file changed.
    Unknown(PathBuf),
}

/// Hot reload manager.
pub struct HotReloadManager {
    config: HotReloadConfig,
    ip_filter: Arc<tokio::sync::RwLock<IpFilter>>,
    acl_manager: Arc<tokio::sync::RwLock<AclManager>>,
    reload_tx: mpsc::Sender<ReloadEvent>,
}

impl HotReloadManager {
    /// Create a new hot reload manager.
    pub fn new(
        config: HotReloadConfig,
        ip_filter: Arc<tokio::sync::RwLock<IpFilter>>,
        acl_manager: Arc<tokio::sync::RwLock<AclManager>>,
    ) -> (Self, mpsc::Receiver<ReloadEvent>) {
        let (reload_tx, reload_rx) = mpsc::channel(32);

        (
            Self {
                config,
                ip_filter,
                acl_manager,
                reload_tx,
            },
            reload_rx,
        )
    }

    /// Start the file watcher background task.
    pub fn start_watcher(
        &self,
        allowlist_path: Option<PathBuf>,
        blocklist_path: Option<PathBuf>,
        acl_config_path: Option<PathBuf>,
    ) -> Result<tokio::task::JoinHandle<()>, notify::Error> {
        let debounce_interval = self.config.debounce_interval;
        let reload_tx = self.reload_tx.clone();
        let ip_filter = self.ip_filter.clone();
        let acl_manager = self.acl_manager.clone();

        // Collect paths to watch
        let mut paths_to_watch: Vec<PathBuf> = self.config.watch_paths.clone();
        if let Some(path) = &allowlist_path {
            paths_to_watch.push(path.clone());
        }
        if let Some(path) = &blocklist_path {
            paths_to_watch.push(path.clone());
        }
        if let Some(path) = &acl_config_path {
            paths_to_watch.push(path.clone());
        }

        if paths_to_watch.is_empty() {
            info!("No files configured for hot reload");
            return Ok(tokio::spawn(async {}));
        }

        info!("Starting hot reload watcher for {} files", paths_to_watch.len());
        for path in &paths_to_watch {
            info!("  Watching: {}", path.display());
        }

        // Clone paths for categorization
        let allowlist_clone = allowlist_path.clone();
        let blocklist_clone = blocklist_path.clone();
        let acl_config_clone = acl_config_path.clone();

        let handle = tokio::spawn(async move {
            // Create a channel to receive file events
            let (tx, mut rx) = mpsc::channel::<PathBuf>(100);

            // Set up the file watcher
            let tx_clone = tx.clone();
            let mut watcher = match RecommendedWatcher::new(
                move |res: Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        for path in event.paths {
                            if let Err(e) = tx_clone.blocking_send(path) {
                                debug!("Failed to send file event: {}", e);
                            }
                        }
                    }
                },
                Config::default().with_poll_interval(Duration::from_secs(2)),
            ) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

            // Add paths to watcher
            for path in &paths_to_watch {
                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                    warn!("Failed to watch {}: {}", path.display(), e);
                }
            }

            // Debounce logic
            let mut pending_events: HashSet<PathBuf> = HashSet::new();
            let mut last_event_time = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    Some(path) = rx.recv() => {
                        pending_events.insert(path);
                        last_event_time = tokio::time::Instant::now();
                    }
                    _ = tokio::time::sleep(debounce_interval) => {
                        if !pending_events.is_empty() &&
                           last_event_time.elapsed() >= debounce_interval
                        {
                            // Process pending events
                            for path in pending_events.drain() {
                                let event = categorize_path(
                                    &path,
                                    allowlist_clone.as_ref(),
                                    blocklist_clone.as_ref(),
                                    acl_config_clone.as_ref(),
                                );

                                info!("Hot reload triggered for {:?}: {}", event, path.display());

                                // Perform the reload
                                match &event {
                                    ReloadEvent::IpFilter => {
                                        if let Err(e) = reload_ip_filter(
                                            &ip_filter,
                                            allowlist_clone.as_ref(),
                                            blocklist_clone.as_ref(),
                                        ).await {
                                            error!("Failed to reload IP filter: {}", e);
                                            metrics::record_config_reload("ip_filter", false);
                                        } else {
                                            info!("IP filter reloaded successfully");
                                            metrics::record_config_reload("ip_filter", true);
                                        }
                                    }
                                    ReloadEvent::AclConfig => {
                                        if let Err(e) = reload_acl_config(
                                            &acl_manager,
                                            acl_config_clone.as_ref(),
                                        ).await {
                                            error!("Failed to reload ACL config: {}", e);
                                            metrics::record_config_reload("acl", false);
                                        } else {
                                            info!("ACL config reloaded successfully");
                                            metrics::record_config_reload("acl", true);
                                        }
                                    }
                                    _ => {
                                        debug!("Ignoring unknown file change: {}", path.display());
                                    }
                                }

                                // Notify listeners
                                let _ = reload_tx.send(event).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }
}

/// Categorize a changed path into a reload event type.
fn categorize_path(
    path: &Path,
    allowlist: Option<&PathBuf>,
    blocklist: Option<&PathBuf>,
    acl_config: Option<&PathBuf>,
) -> ReloadEvent {
    if allowlist.map(|p| p == path).unwrap_or(false)
        || blocklist.map(|p| p == path).unwrap_or(false)
    {
        ReloadEvent::IpFilter
    } else if acl_config.map(|p| p == path).unwrap_or(false) {
        ReloadEvent::AclConfig
    } else {
        ReloadEvent::Unknown(path.to_path_buf())
    }
}

/// Reload the IP filter from files.
async fn reload_ip_filter(
    ip_filter: &Arc<tokio::sync::RwLock<IpFilter>>,
    allowlist: Option<&PathBuf>,
    blocklist: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::ipfilter::IpFilterConfig;

    let config = IpFilterConfig {
        allowlist_file: allowlist.map(|p| p.to_string_lossy().to_string()),
        blocklist_file: blocklist.map(|p| p.to_string_lossy().to_string()),
        allow_all_if_empty: true,
    };

    let new_filter = IpFilter::from_config(&config);

    let mut filter = ip_filter.write().await;
    *filter = new_filter;

    Ok(())
}

/// Reload the ACL configuration from a YAML file.
async fn reload_acl_config(
    acl_manager: &Arc<tokio::sync::RwLock<AclManager>>,
    acl_config_path: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = acl_config_path.ok_or("No ACL config path specified")?;
    
    // Read and parse the YAML file
    let content = tokio::fs::read_to_string(path).await?;
    let config: AclFileConfig = serde_yaml::from_str(&content)?;

    // Update the ACL manager with new rules
    let mut manager = acl_manager.write().await;
    manager.clear_rules();

    for rule in config.subdomains {
        manager.add_subdomain_rule(
            &rule.subdomain,
            crate::acl::SubdomainAclConfig {
                enabled: rule.enabled.unwrap_or(true),
                ip_allowlist: rule.ip_allowlist.unwrap_or_default(),
                ip_blocklist: rule.ip_blocklist.unwrap_or_default(),
                rate_limit_rps: rule.rate_limit_rps,
                rate_limit_burst: rule.rate_limit_burst,
                max_connections: rule.max_connections,
                max_body_size: rule.max_body_size,
            },
        );
    }

    Ok(())
}

/// Structure for parsing ACL YAML configuration file.
#[derive(Debug, Clone, serde::Deserialize)]
struct AclFileConfig {
    #[serde(default)]
    subdomains: Vec<SubdomainConfig>,
}

/// Per-subdomain configuration from YAML.
#[derive(Debug, Clone, serde::Deserialize)]
struct SubdomainConfig {
    subdomain: String,
    enabled: Option<bool>,
    ip_allowlist: Option<Vec<String>>,
    ip_blocklist: Option<Vec<String>>,
    rate_limit_rps: Option<u32>,
    rate_limit_burst: Option<u32>,
    max_connections: Option<usize>,
    max_body_size: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_reload_config() {
        let config = HotReloadConfig::new(vec![PathBuf::from("/tmp/test.txt")])
            .debounce(Duration::from_secs(5));

        assert!(config.enabled);
        assert_eq!(config.watch_paths.len(), 1);
        assert_eq!(config.debounce_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_categorize_path() {
        let allowlist = PathBuf::from("/etc/allowlist.txt");
        let blocklist = PathBuf::from("/etc/blocklist.txt");
        let acl_config = PathBuf::from("/etc/acl.yaml");

        assert_eq!(
            categorize_path(&allowlist, Some(&allowlist), Some(&blocklist), Some(&acl_config)),
            ReloadEvent::IpFilter
        );

        assert_eq!(
            categorize_path(&acl_config, Some(&allowlist), Some(&blocklist), Some(&acl_config)),
            ReloadEvent::AclConfig
        );

        assert!(matches!(
            categorize_path(&PathBuf::from("/other/file.txt"), Some(&allowlist), Some(&blocklist), Some(&acl_config)),
            ReloadEvent::Unknown(_)
        ));
    }
}

