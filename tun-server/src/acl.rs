//! Per-subdomain access control and rate limits.
//!
//! Provides fine-grained control over what subdomains can do,
//! including rate limits, allowed IPs, and maximum connections.

use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Access control rule for a subdomain.
#[derive(Debug, Clone)]
pub struct SubdomainAcl {
    /// Subdomain this rule applies to.
    pub subdomain: String,
    /// Allowed IP addresses (empty = all allowed).
    pub allowed_ips: HashSet<IpAddr>,
    /// Blocked IP addresses.
    pub blocked_ips: HashSet<IpAddr>,
    /// Rate limit (requests per second).
    pub rate_limit_rps: Option<u32>,
    /// Rate limit burst size.
    pub rate_limit_burst: Option<u32>,
    /// Maximum concurrent connections.
    pub max_connections: Option<u32>,
    /// Maximum body size in bytes.
    pub max_body_size: Option<usize>,
    /// Whether the subdomain is enabled.
    pub enabled: bool,
    /// Optional comment/description.
    pub description: Option<String>,
}

impl Default for SubdomainAcl {
    fn default() -> Self {
        Self {
            subdomain: String::new(),
            allowed_ips: HashSet::new(),
            blocked_ips: HashSet::new(),
            rate_limit_rps: None,
            rate_limit_burst: None,
            max_connections: None,
            max_body_size: None,
            enabled: true,
            description: None,
        }
    }
}

impl SubdomainAcl {
    /// Create a new ACL rule for a subdomain.
    pub fn new(subdomain: &str) -> Self {
        Self {
            subdomain: subdomain.to_string(),
            ..Default::default()
        }
    }

    /// Allow a specific IP address.
    pub fn allow_ip(mut self, ip: IpAddr) -> Self {
        self.allowed_ips.insert(ip);
        self
    }

    /// Block a specific IP address.
    pub fn block_ip(mut self, ip: IpAddr) -> Self {
        self.blocked_ips.insert(ip);
        self
    }

    /// Set rate limit.
    pub fn with_rate_limit(mut self, rps: u32, burst: u32) -> Self {
        self.rate_limit_rps = Some(rps);
        self.rate_limit_burst = Some(burst);
        self
    }

    /// Set maximum connections.
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Set maximum body size.
    pub fn with_max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = Some(max);
        self
    }

    /// Disable the subdomain.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Check if an IP is allowed.
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        // If blocked, deny
        if self.blocked_ips.contains(&ip) {
            return false;
        }

        // If there's an allow list, IP must be in it
        if !self.allowed_ips.is_empty() && !self.allowed_ips.contains(&ip) {
            return false;
        }

        true
    }
}

/// Rate limiter state for a subdomain.
struct SubdomainRateLimiter {
    tokens: f64,
    last_update: Instant,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl SubdomainRateLimiter {
    fn new(rps: u32, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            last_update: Instant::now(),
            max_tokens: burst as f64,
            refill_rate: rps as f64,
        }
    }

    fn check(&mut self) -> bool {
        // Refill tokens
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;

        // Check if we have a token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Access control manager.
pub struct AclManager {
    /// Per-subdomain ACL rules.
    rules: DashMap<String, SubdomainAcl>,
    /// Per-subdomain rate limiters.
    rate_limiters: DashMap<(String, IpAddr), SubdomainRateLimiter>,
    /// Per-subdomain connection counts.
    connection_counts: DashMap<String, u32>,
    /// Default ACL for subdomains without specific rules.
    default_acl: SubdomainAcl,
}

impl AclManager {
    /// Create a new ACL manager.
    pub fn new() -> Self {
        Self {
            rules: DashMap::new(),
            rate_limiters: DashMap::new(),
            connection_counts: DashMap::new(),
            default_acl: SubdomainAcl::default(),
        }
    }

    /// Create with a default ACL.
    pub fn with_default_acl(default_acl: SubdomainAcl) -> Self {
        Self {
            rules: DashMap::new(),
            rate_limiters: DashMap::new(),
            connection_counts: DashMap::new(),
            default_acl,
        }
    }

    /// Add an ACL rule for a subdomain.
    pub fn add_rule(&self, acl: SubdomainAcl) {
        info!(
            "Adding ACL rule for subdomain '{}': enabled={}, rate_limit={:?}",
            acl.subdomain, acl.enabled, acl.rate_limit_rps
        );
        self.rules.insert(acl.subdomain.clone(), acl);
    }

    /// Remove an ACL rule.
    pub fn remove_rule(&self, subdomain: &str) {
        self.rules.remove(subdomain);
    }

    /// Get the ACL for a subdomain.
    pub fn get_acl(&self, subdomain: &str) -> SubdomainAcl {
        self.rules
            .get(subdomain)
            .map(|r| r.clone())
            .unwrap_or_else(|| {
                let mut default = self.default_acl.clone();
                default.subdomain = subdomain.to_string();
                default
            })
    }

    /// Check if a request is allowed.
    pub fn check_request(
        &self,
        subdomain: &str,
        client_ip: IpAddr,
        body_size: usize,
    ) -> Result<(), AclDenied> {
        let acl = self.get_acl(subdomain);

        // Check if enabled
        if !acl.enabled {
            debug!("Subdomain '{}' is disabled", subdomain);
            return Err(AclDenied::SubdomainDisabled);
        }

        // Check IP
        if !acl.is_ip_allowed(client_ip) {
            debug!(
                "IP {} is not allowed for subdomain '{}'",
                client_ip, subdomain
            );
            return Err(AclDenied::IpNotAllowed);
        }

        // Check body size
        if let Some(max_body) = acl.max_body_size {
            if body_size > max_body {
                debug!(
                    "Body size {} exceeds limit {} for subdomain '{}'",
                    body_size, max_body, subdomain
                );
                return Err(AclDenied::BodyTooLarge);
            }
        }

        // Check rate limit
        if let (Some(rps), Some(burst)) = (acl.rate_limit_rps, acl.rate_limit_burst) {
            let key = (subdomain.to_string(), client_ip);
            let mut limiter = self
                .rate_limiters
                .entry(key)
                .or_insert_with(|| SubdomainRateLimiter::new(rps, burst));
            if !limiter.check() {
                debug!(
                    "Rate limit exceeded for IP {} on subdomain '{}'",
                    client_ip, subdomain
                );
                return Err(AclDenied::RateLimitExceeded);
            }
        }

        Ok(())
    }

    /// Register a new connection.
    pub fn register_connection(&self, subdomain: &str) -> Result<(), AclDenied> {
        let acl = self.get_acl(subdomain);

        if let Some(max) = acl.max_connections {
            let mut count = self.connection_counts.entry(subdomain.to_string()).or_insert(0);
            if *count >= max {
                debug!(
                    "Max connections ({}) reached for subdomain '{}'",
                    max, subdomain
                );
                return Err(AclDenied::MaxConnectionsReached);
            }
            *count += 1;
        }

        Ok(())
    }

    /// Unregister a connection.
    pub fn unregister_connection(&self, subdomain: &str) {
        if let Some(mut count) = self.connection_counts.get_mut(subdomain) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Cleanup expired rate limiters.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.rate_limiters.retain(|_, v| {
            now.duration_since(v.last_update) < max_age
        });
    }

    /// Clear all rules (for hot reload).
    pub fn clear_rules(&mut self) {
        self.rules.clear();
        self.rate_limiters.clear();
        self.connection_counts.clear();
        info!("Cleared all ACL rules");
    }

    /// Add a subdomain rule from config (for hot reload).
    pub fn add_subdomain_rule(&mut self, subdomain: &str, config: SubdomainAclConfig) {
        let mut acl = SubdomainAcl::new(subdomain);
        acl.enabled = config.enabled;
        
        // Parse IP allowlist
        for ip_str in config.ip_allowlist {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                acl.allowed_ips.insert(ip);
            }
        }
        
        // Parse IP blocklist
        for ip_str in config.ip_blocklist {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                acl.blocked_ips.insert(ip);
            }
        }
        
        acl.rate_limit_rps = config.rate_limit_rps;
        acl.rate_limit_burst = config.rate_limit_burst;
        acl.max_connections = config.max_connections.map(|n| n as u32);
        acl.max_body_size = config.max_body_size;
        
        self.add_rule(acl);
    }
}

/// Configuration for subdomain ACL from external config file.
#[derive(Debug, Clone, Default)]
pub struct SubdomainAclConfig {
    pub enabled: bool,
    pub ip_allowlist: Vec<String>,
    pub ip_blocklist: Vec<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub max_connections: Option<usize>,
    pub max_body_size: Option<usize>,
}

impl Default for AclManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Reason for ACL denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDenied {
    /// Subdomain is disabled.
    SubdomainDisabled,
    /// IP is not allowed.
    IpNotAllowed,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Maximum connections reached.
    MaxConnectionsReached,
    /// Body size too large.
    BodyTooLarge,
}

impl std::fmt::Display for AclDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclDenied::SubdomainDisabled => write!(f, "subdomain is disabled"),
            AclDenied::IpNotAllowed => write!(f, "IP address not allowed"),
            AclDenied::RateLimitExceeded => write!(f, "rate limit exceeded"),
            AclDenied::MaxConnectionsReached => write!(f, "maximum connections reached"),
            AclDenied::BodyTooLarge => write!(f, "request body too large"),
        }
    }
}

impl std::error::Error for AclDenied {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_subdomain_acl() {
        let acl = SubdomainAcl::new("test")
            .allow_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
            .with_rate_limit(100, 200);

        assert!(acl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!acl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
    }

    #[test]
    fn test_acl_manager() {
        let manager = AclManager::new();
        
        let acl = SubdomainAcl::new("test")
            .with_rate_limit(10, 20)
            .with_max_body_size(1024);
        manager.add_rule(acl);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        
        // Should allow
        assert!(manager.check_request("test", ip, 512).is_ok());
        
        // Should deny body too large
        assert_eq!(
            manager.check_request("test", ip, 2048),
            Err(AclDenied::BodyTooLarge)
        );
    }

    #[test]
    fn test_disabled_subdomain() {
        let manager = AclManager::new();
        
        let acl = SubdomainAcl::new("disabled").disabled();
        manager.add_rule(acl);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(
            manager.check_request("disabled", ip, 0),
            Err(AclDenied::SubdomainDisabled)
        );
    }
}

