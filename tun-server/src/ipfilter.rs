//! IP-based filtering with allow and block lists.
//!
//! Supports individual IP addresses and CIDR notation for network ranges.

use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;
use tracing::{debug, info, warn};

/// IP filter configuration.
#[derive(Debug, Clone, Default)]
pub struct IpFilterConfig {
    /// Path to allowlist file (one IP/CIDR per line)
    pub allowlist_file: Option<String>,
    /// Path to blocklist file (one IP/CIDR per line)
    pub blocklist_file: Option<String>,
    /// Whether to allow all if allowlist is empty
    pub allow_all_if_empty: bool,
}

/// IP filter that checks IPs against allow and block lists.
pub struct IpFilter {
    /// Individual IPs in allowlist
    allowlist_ips: RwLock<HashSet<IpAddr>>,
    /// CIDR ranges in allowlist
    allowlist_cidrs: RwLock<Vec<IpNet>>,
    /// Individual IPs in blocklist
    blocklist_ips: RwLock<HashSet<IpAddr>>,
    /// CIDR ranges in blocklist
    blocklist_cidrs: RwLock<Vec<IpNet>>,
    /// Whether to allow all if allowlist is empty
    allow_all_if_empty: bool,
}

impl IpFilter {
    /// Create a new IP filter that allows all traffic.
    pub fn allow_all() -> Self {
        Self {
            allowlist_ips: RwLock::new(HashSet::new()),
            allowlist_cidrs: RwLock::new(Vec::new()),
            blocklist_ips: RwLock::new(HashSet::new()),
            blocklist_cidrs: RwLock::new(Vec::new()),
            allow_all_if_empty: true,
        }
    }

    /// Create a new IP filter from configuration.
    pub fn from_config(config: &IpFilterConfig) -> Self {
        let mut filter = Self {
            allowlist_ips: RwLock::new(HashSet::new()),
            allowlist_cidrs: RwLock::new(Vec::new()),
            blocklist_ips: RwLock::new(HashSet::new()),
            blocklist_cidrs: RwLock::new(Vec::new()),
            allow_all_if_empty: config.allow_all_if_empty,
        };

        if let Some(ref path) = config.allowlist_file {
            if let Err(e) = filter.load_allowlist(path) {
                warn!("Failed to load allowlist from {}: {}", path, e);
            }
        }

        if let Some(ref path) = config.blocklist_file {
            if let Err(e) = filter.load_blocklist(path) {
                warn!("Failed to load blocklist from {}: {}", path, e);
            }
        }

        filter
    }

    /// Load allowlist from a file.
    pub fn load_allowlist(&self, path: &str) -> Result<usize, std::io::Error> {
        let (ips, cidrs) = load_ip_list(path)?;
        let count = ips.len() + cidrs.len();
        
        *self.allowlist_ips.write().unwrap() = ips;
        *self.allowlist_cidrs.write().unwrap() = cidrs;
        
        info!("Loaded {} allowlist entries from {}", count, path);
        Ok(count)
    }

    /// Load blocklist from a file.
    pub fn load_blocklist(&self, path: &str) -> Result<usize, std::io::Error> {
        let (ips, cidrs) = load_ip_list(path)?;
        let count = ips.len() + cidrs.len();
        
        *self.blocklist_ips.write().unwrap() = ips;
        *self.blocklist_cidrs.write().unwrap() = cidrs;
        
        info!("Loaded {} blocklist entries from {}", count, path);
        Ok(count)
    }

    /// Add an IP to the allowlist.
    pub fn allow_ip(&self, ip: IpAddr) {
        self.allowlist_ips.write().unwrap().insert(ip);
    }

    /// Add a CIDR to the allowlist.
    pub fn allow_cidr(&self, cidr: IpNet) {
        self.allowlist_cidrs.write().unwrap().push(cidr);
    }

    /// Add an IP to the blocklist.
    pub fn block_ip(&self, ip: IpAddr) {
        self.blocklist_ips.write().unwrap().insert(ip);
    }

    /// Add a CIDR to the blocklist.
    pub fn block_cidr(&self, cidr: IpNet) {
        self.blocklist_cidrs.write().unwrap().push(cidr);
    }

    /// Remove an IP from the blocklist.
    pub fn unblock_ip(&self, ip: &IpAddr) {
        self.blocklist_ips.write().unwrap().remove(ip);
    }

    /// Check if an IP is allowed.
    /// Returns true if the IP is allowed, false if blocked.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // First check blocklist - if blocked, deny
        if self.is_blocked(&ip) {
            debug!("IP {} is blocked", ip);
            return false;
        }

        // Then check allowlist
        let allowlist_ips = self.allowlist_ips.read().unwrap();
        let allowlist_cidrs = self.allowlist_cidrs.read().unwrap();

        // If allowlist is empty and allow_all_if_empty is true, allow
        if allowlist_ips.is_empty() && allowlist_cidrs.is_empty() {
            return self.allow_all_if_empty;
        }

        // Check individual IP
        if allowlist_ips.contains(&ip) {
            return true;
        }

        // Check CIDR ranges
        for cidr in allowlist_cidrs.iter() {
            if cidr.contains(&ip) {
                return true;
            }
        }

        // Not in allowlist
        debug!("IP {} not in allowlist", ip);
        false
    }

    /// Check if an IP is in the blocklist.
    fn is_blocked(&self, ip: &IpAddr) -> bool {
        let blocklist_ips = self.blocklist_ips.read().unwrap();
        let blocklist_cidrs = self.blocklist_cidrs.read().unwrap();

        // Check individual IP
        if blocklist_ips.contains(ip) {
            return true;
        }

        // Check CIDR ranges
        for cidr in blocklist_cidrs.iter() {
            if cidr.contains(ip) {
                return true;
            }
        }

        false
    }

    /// Get the number of allowlist entries.
    pub fn allowlist_count(&self) -> usize {
        self.allowlist_ips.read().unwrap().len() + 
        self.allowlist_cidrs.read().unwrap().len()
    }

    /// Get the number of blocklist entries.
    pub fn blocklist_count(&self) -> usize {
        self.blocklist_ips.read().unwrap().len() + 
        self.blocklist_cidrs.read().unwrap().len()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.allowlist_ips.write().unwrap().clear();
        self.allowlist_cidrs.write().unwrap().clear();
        self.blocklist_ips.write().unwrap().clear();
        self.blocklist_cidrs.write().unwrap().clear();
    }
}

impl Default for IpFilter {
    fn default() -> Self {
        Self::allow_all()
    }
}

/// Load IP list from a file.
/// Returns (individual IPs, CIDR ranges).
fn load_ip_list(path: &str) -> Result<(HashSet<IpAddr>, Vec<IpNet>), std::io::Error> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(Path::new(path))?;
    let reader = BufReader::new(file);

    let mut ips = HashSet::new();
    let mut cidrs = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Try to parse as CIDR first
        if let Ok(cidr) = line.parse::<IpNet>() {
            cidrs.push(cidr);
            continue;
        }

        // Try to parse as IP
        if let Ok(ip) = line.parse::<IpAddr>() {
            ips.insert(ip);
            continue;
        }

        warn!("Invalid IP/CIDR entry: {}", line);
    }

    Ok((ips, cidrs))
}

/// Parsed IP entry - either an individual IP or a CIDR range.
#[derive(Debug, Clone)]
pub enum IpEntry {
    /// Individual IP address
    Ip(IpAddr),
    /// CIDR range
    Cidr(IpNet),
}

/// Parse an IP or CIDR string.
pub fn parse_ip_or_cidr(s: &str) -> Result<IpEntry, String> {
    // Try CIDR first
    if s.contains('/') {
        s.parse::<IpNet>()
            .map(IpEntry::Cidr)
            .map_err(|e| format!("Invalid CIDR: {}", e))
    } else {
        s.parse::<IpAddr>()
            .map(IpEntry::Ip)
            .map_err(|e| format!("Invalid IP: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_allow_all() {
        let filter = IpFilter::allow_all();
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_blocklist() {
        let filter = IpFilter::allow_all();
        let blocked_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        
        filter.block_ip(blocked_ip);
        assert!(!filter.is_allowed(blocked_ip));
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_allowlist() {
        let filter = IpFilter {
            allowlist_ips: RwLock::new(HashSet::new()),
            allowlist_cidrs: RwLock::new(Vec::new()),
            blocklist_ips: RwLock::new(HashSet::new()),
            blocklist_cidrs: RwLock::new(Vec::new()),
            allow_all_if_empty: false,
        };
        
        let allowed_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        filter.allow_ip(allowed_ip);
        
        assert!(filter.is_allowed(allowed_ip));
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_cidr_blocklist() {
        let filter = IpFilter::allow_all();
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        
        filter.block_cidr(cidr);
        
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254))));
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[test]
    fn test_cidr_allowlist() {
        let filter = IpFilter {
            allowlist_ips: RwLock::new(HashSet::new()),
            allowlist_cidrs: RwLock::new(Vec::new()),
            blocklist_ips: RwLock::new(HashSet::new()),
            blocklist_cidrs: RwLock::new(Vec::new()),
            allow_all_if_empty: false,
        };
        
        let cidr: IpNet = "10.0.0.0/8".parse().unwrap();
        filter.allow_cidr(cidr);
        
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 254))));
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_blocklist_takes_precedence() {
        let filter = IpFilter::allow_all();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        
        // Add to both allowlist and blocklist
        filter.allow_ip(ip);
        filter.block_ip(ip);
        
        // Blocklist should take precedence
        assert!(!filter.is_allowed(ip));
    }

    #[test]
    fn test_ipv6() {
        let filter = IpFilter::allow_all();
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        
        assert!(filter.is_allowed(ipv6));
        
        filter.block_ip(ipv6);
        assert!(!filter.is_allowed(ipv6));
    }
}

