//! Rate limiting middleware for tunnel server.
//!
//! Provides IP-based, subdomain-based, and token-based rate limiting for both
//! the control plane and proxy endpoints using the governor crate with Tower
//! integration. Includes LRU-based cleanup to bound memory usage.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response, StatusCode},
};
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use lru::LruCache;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Instant,
};
use tower::{Layer, Service};
use tracing::{debug, info, warn};
use uuid::Uuid;
use serde_json;

// Re-export TrustedProxyFilter from proxy module
pub use crate::proxy::TrustedProxyFilter;

/// Default maximum number of IPs to track.
const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;

/// Configuration for rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second per IP
    pub requests_per_second: u32,
    /// Burst size (allows temporary spikes above the rate)
    pub burst_size: u32,
    /// Maximum number of IPs to track (LRU eviction after this)
    pub max_tracked_ips: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 200,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
        }
    }
}

impl RateLimitConfig {
    pub fn new(requests_per_second: u32, burst_size: u32) -> Self {
        Self {
            requests_per_second,
            burst_size,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
        }
    }

    /// Create a config with custom max tracked IPs.
    pub fn with_max_tracked_ips(mut self, max_tracked_ips: usize) -> Self {
        self.max_tracked_ips = max_tracked_ips;
        self
    }

    /// Create a Quota from this configuration.
    pub fn to_quota(&self) -> Quota {
        Quota::per_second(NonZeroU32::new(self.requests_per_second).unwrap_or(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(self.burst_size).unwrap_or(NonZeroU32::MIN))
    }
}

/// Entry in the LRU cache for rate limiting.
struct RateLimitEntry {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    last_access: Instant,
}

/// Per-IP rate limiter with LRU-based memory management.
pub struct IpRateLimiter {
    /// LRU cache of rate limiters by IP
    cache: Mutex<LruCache<IpAddr, RateLimitEntry>>,
    /// Quota configuration
    quota: Quota,
    /// Maximum number of IPs to track
    max_tracked_ips: usize,
    /// Counter for rate limited requests (for metrics)
    rate_limited_count: std::sync::atomic::AtomicU64,
}

impl IpRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let capacity = NonZeroUsize::new(config.max_tracked_ips).unwrap_or(NonZeroUsize::MIN);
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            quota: config.to_quota(),
            max_tracked_ips: config.max_tracked_ips,
            rate_limited_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check if a request from the given IP should be allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut cache = self.cache.lock().unwrap();

        // Get or create entry for this IP
        let entry = cache.get_or_insert_mut(ip, || RateLimitEntry {
            limiter: RateLimiter::direct(self.quota),
            last_access: Instant::now(),
        });

        // Update last access time
        entry.last_access = Instant::now();

        // Check rate limit
        let allowed = entry.limiter.check().is_ok();
        if !allowed {
            self.rate_limited_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        allowed
    }

    /// Get the number of tracked IPs (for monitoring).
    pub fn tracked_ips(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Get the number of rate limited requests since creation.
    pub fn rate_limited_count(&self) -> u64 {
        self.rate_limited_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Clean up old entries that haven't been accessed recently.
    /// This is in addition to the LRU eviction that happens automatically.
    pub fn cleanup(&self, max_age_secs: u64) {
        let mut cache = self.cache.lock().unwrap();
        let cutoff = Instant::now() - std::time::Duration::from_secs(max_age_secs);

        // Collect keys to remove (can't modify during iteration)
        let keys_to_remove: Vec<IpAddr> = cache
            .iter()
            .filter(|(_, entry)| entry.last_access < cutoff)
            .map(|(ip, _)| *ip)
            .collect();

        let removed = keys_to_remove.len();
        for ip in keys_to_remove {
            cache.pop(&ip);
        }

        if removed > 0 {
            info!("Rate limiter cleanup: removed {} stale entries", removed);
        }
    }

    /// Get the maximum capacity.
    pub fn max_capacity(&self) -> usize {
        self.max_tracked_ips
    }
}

/// Tower Layer for rate limiting.
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<IpRateLimiter>,
    trusted_proxies: Arc<TrustedProxyFilter>,
}

impl RateLimitLayer {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            limiter: Arc::new(IpRateLimiter::new(config)),
            trusted_proxies: Arc::new(TrustedProxyFilter::default()),
        }
    }

    pub fn from_limiter(limiter: Arc<IpRateLimiter>) -> Self {
        Self {
            limiter,
            trusted_proxies: Arc::new(TrustedProxyFilter::default()),
        }
    }

    /// Set the trusted proxy filter for secure X-Forwarded-For handling.
    pub fn with_trusted_proxies(mut self, filter: TrustedProxyFilter) -> Self {
        self.trusted_proxies = Arc::new(filter);
        self
    }

    /// Set the trusted proxy filter from an Arc.
    pub fn with_trusted_proxies_arc(mut self, filter: Arc<TrustedProxyFilter>) -> Self {
        self.trusted_proxies = filter;
        self
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
            trusted_proxies: self.trusted_proxies.clone(),
        }
    }
}

/// Tower Service for rate limiting.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: Arc<IpRateLimiter>,
    trusted_proxies: Arc<TrustedProxyFilter>,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Try to extract IP from ConnectInfo or headers, using trusted proxy filter
        let ip = extract_client_ip(&req, &self.trusted_proxies);

        let limiter = self.limiter.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if let Some(ip) = ip {
                if !limiter.check(ip) {
                    warn!("Rate limit exceeded for IP: {}", ip);
                    return Ok(rate_limit_response());
                }
                debug!("Rate limit check passed for IP: {}", ip);
            }

            inner.call(req).await
        })
    }
}

/// Extract client IP from request with trusted proxy validation.
/// Only trusts X-Forwarded-For and X-Real-IP headers if the direct connection
/// is from a trusted proxy. Otherwise, uses the direct connection IP.
fn extract_client_ip<B>(req: &Request<B>, trusted_proxies: &TrustedProxyFilter) -> Option<IpAddr> {
    // Get the direct connection IP first
    let direct_ip = req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    let Some(direct_ip) = direct_ip else {
        return None;
    };

    // Only trust forwarded headers if connection is from a trusted proxy
    if !trusted_proxies.is_trusted(direct_ip) {
        debug!("Direct IP {} is not a trusted proxy, ignoring forwarded headers", direct_ip);
        return Some(direct_ip);
    }

    // Check X-Forwarded-For header (common when behind a proxy)
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            // Take the first IP in the list (original client)
            if let Some(ip_str) = value.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    debug!("Using client IP {} from X-Forwarded-For (trusted proxy: {})", ip, direct_ip);
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header (nginx)
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.parse::<IpAddr>() {
                debug!("Using client IP {} from X-Real-IP (trusted proxy: {})", ip, direct_ip);
                return Some(ip);
            }
        }
    }

    // Fall back to direct connection IP
    Some(direct_ip)
}

/// Create a 429 Too Many Requests response with request ID for tracing.
fn rate_limit_response() -> Response<Body> {
    let request_id = Uuid::new_v4().to_string();
    let body = serde_json::json!({
        "error": {
            "code": "rate_limit_exceeded",
            "message": "Rate limit exceeded. Please slow down.",
            "status": 429,
            "request_id": request_id,
            "retryable": true
        }
    });

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Content-Type", "application/json")
        .header("X-Request-Id", &request_id)
        .header("Retry-After", "1")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"error":{"code":"internal_error","message":"Internal server error"}}"#))
                .unwrap()
        })
}

/// Create a shared rate limiter that can be used across multiple services.
pub fn create_shared_limiter(config: &RateLimitConfig) -> Arc<IpRateLimiter> {
    Arc::new(IpRateLimiter::new(config))
}

/// Entry in the subdomain rate limit cache.
struct SubdomainRateLimitEntry {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    last_access: Instant,
}

/// Per-subdomain rate limiter with LRU-based memory management.
/// Limits requests by subdomain to prevent a single tunnel from overwhelming the service.
pub struct SubdomainRateLimiter {
    /// LRU cache of rate limiters by subdomain
    cache: Mutex<LruCache<String, SubdomainRateLimitEntry>>,
    /// Default quota configuration
    default_quota: Quota,
    /// Per-subdomain custom quotas
    custom_quotas: DashMap<String, Quota>,
    /// Counter for rate limited requests
    rate_limited_count: std::sync::atomic::AtomicU64,
}

impl SubdomainRateLimiter {
    /// Create a new subdomain rate limiter.
    pub fn new(config: &RateLimitConfig) -> Self {
        let capacity = NonZeroUsize::new(config.max_tracked_ips).unwrap_or(NonZeroUsize::MIN);
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            default_quota: config.to_quota(),
            custom_quotas: dashmap::DashMap::new(),
            rate_limited_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set a custom quota for a specific subdomain.
    pub fn set_subdomain_quota(&self, subdomain: &str, rps: u32, burst: u32) {
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap_or(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN));
        self.custom_quotas.insert(subdomain.to_string(), quota);
        info!("Set custom rate limit for subdomain '{}': {} rps, {} burst", subdomain, rps, burst);
    }

    /// Remove a custom quota for a subdomain (reverts to default).
    pub fn remove_subdomain_quota(&self, subdomain: &str) {
        self.custom_quotas.remove(subdomain);
    }

    /// Check if a request to the given subdomain should be allowed.
    pub fn check(&self, subdomain: &str) -> bool {
        let mut cache = self.cache.lock().unwrap();
        
        // Get the appropriate quota for this subdomain
        let quota = self.custom_quotas
            .get(subdomain)
            .map(|q| *q)
            .unwrap_or(self.default_quota);

        // Get or create entry for this subdomain
        let entry = cache.get_or_insert_mut(subdomain.to_string(), || SubdomainRateLimitEntry {
            limiter: RateLimiter::direct(quota),
            last_access: Instant::now(),
        });

        entry.last_access = Instant::now();

        let allowed = entry.limiter.check().is_ok();
        if !allowed {
            self.rate_limited_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("Rate limit exceeded for subdomain: {}", subdomain);
        }

        allowed
    }

    /// Get the number of tracked subdomains.
    pub fn tracked_subdomains(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Get the number of rate limited requests.
    pub fn rate_limited_count(&self) -> u64 {
        self.rate_limited_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Clean up old entries.
    pub fn cleanup(&self, max_age_secs: u64) {
        let mut cache = self.cache.lock().unwrap();
        let cutoff = Instant::now() - std::time::Duration::from_secs(max_age_secs);

        let keys_to_remove: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.last_access < cutoff)
            .map(|(subdomain, _)| subdomain.clone())
            .collect();

        let removed = keys_to_remove.len();
        for subdomain in keys_to_remove {
            cache.pop(&subdomain);
        }

        if removed > 0 {
            info!("Subdomain rate limiter cleanup: removed {} stale entries", removed);
        }
    }
}

/// Entry in the token rate limit cache.
struct TokenRateLimitEntry {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    last_access: Instant,
}

/// Per-token rate limiter for controlling tunnel usage.
/// Limits requests by authentication token to enforce fair usage.
pub struct TokenRateLimiter {
    /// LRU cache of rate limiters by token ID
    cache: Mutex<LruCache<String, TokenRateLimitEntry>>,
    /// Default quota configuration
    default_quota: Quota,
    /// Per-token custom quotas
    custom_quotas: DashMap<String, Quota>,
    /// Counter for rate limited requests
    rate_limited_count: std::sync::atomic::AtomicU64,
}

impl TokenRateLimiter {
    /// Create a new token rate limiter.
    pub fn new(config: &RateLimitConfig) -> Self {
        let capacity = NonZeroUsize::new(config.max_tracked_ips).unwrap_or(NonZeroUsize::MIN);
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            default_quota: config.to_quota(),
            custom_quotas: dashmap::DashMap::new(),
            rate_limited_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set a custom quota for a specific token.
    pub fn set_token_quota(&self, token_id: &str, rps: u32, burst: u32) {
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap_or(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN));
        self.custom_quotas.insert(token_id.to_string(), quota);
        info!("Set custom rate limit for token '{}': {} rps, {} burst", token_id, rps, burst);
    }

    /// Remove a custom quota for a token.
    pub fn remove_token_quota(&self, token_id: &str) {
        self.custom_quotas.remove(token_id);
    }

    /// Check if a request with the given token should be allowed.
    pub fn check(&self, token_id: &str) -> bool {
        let mut cache = self.cache.lock().unwrap();
        
        let quota = self.custom_quotas
            .get(token_id)
            .map(|q| *q)
            .unwrap_or(self.default_quota);

        let entry = cache.get_or_insert_mut(token_id.to_string(), || TokenRateLimitEntry {
            limiter: RateLimiter::direct(quota),
            last_access: Instant::now(),
        });

        entry.last_access = Instant::now();

        let allowed = entry.limiter.check().is_ok();
        if !allowed {
            self.rate_limited_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("Rate limit exceeded for token: {}", token_id);
        }

        allowed
    }

    /// Get the number of tracked tokens.
    pub fn tracked_tokens(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Get the number of rate limited requests.
    pub fn rate_limited_count(&self) -> u64 {
        self.rate_limited_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Clean up old entries.
    pub fn cleanup(&self, max_age_secs: u64) {
        let mut cache = self.cache.lock().unwrap();
        let cutoff = Instant::now() - std::time::Duration::from_secs(max_age_secs);

        let keys_to_remove: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.last_access < cutoff)
            .map(|(token_id, _)| token_id.clone())
            .collect();

        let removed = keys_to_remove.len();
        for token_id in keys_to_remove {
            cache.pop(&token_id);
        }

        if removed > 0 {
            info!("Token rate limiter cleanup: removed {} stale entries", removed);
        }
    }
}

/// Combined rate limiter that checks IP, subdomain, and token limits.
pub struct CombinedRateLimiter {
    /// IP-based rate limiter
    pub ip_limiter: Arc<IpRateLimiter>,
    /// Subdomain-based rate limiter
    pub subdomain_limiter: Arc<SubdomainRateLimiter>,
    /// Token-based rate limiter (optional)
    pub token_limiter: Option<Arc<TokenRateLimiter>>,
}

impl CombinedRateLimiter {
    /// Create a new combined rate limiter.
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            ip_limiter: Arc::new(IpRateLimiter::new(config)),
            subdomain_limiter: Arc::new(SubdomainRateLimiter::new(config)),
            token_limiter: None,
        }
    }

    /// Enable token-based rate limiting.
    pub fn with_token_limiter(mut self, config: &RateLimitConfig) -> Self {
        self.token_limiter = Some(Arc::new(TokenRateLimiter::new(config)));
        self
    }

    /// Check all applicable rate limits.
    /// Returns None if allowed, or Some(reason) if rate limited.
    pub fn check(&self, ip: IpAddr, subdomain: &str, token_id: Option<&str>) -> Option<&'static str> {
        // Check IP limit first
        if !self.ip_limiter.check(ip) {
            return Some("ip");
        }

        // Check subdomain limit
        if !self.subdomain_limiter.check(subdomain) {
            return Some("subdomain");
        }

        // Check token limit if enabled and token provided
        if let (Some(ref limiter), Some(token_id)) = (&self.token_limiter, token_id) {
            if !limiter.check(token_id) {
                return Some("token");
            }
        }

        None
    }

    /// Clean up all rate limiters.
    pub fn cleanup(&self, max_age_secs: u64) {
        self.ip_limiter.cleanup(max_age_secs);
        self.subdomain_limiter.cleanup(max_age_secs);
        if let Some(ref limiter) = self.token_limiter {
            limiter.cleanup(max_age_secs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_second, 100);
        assert_eq!(config.burst_size, 200);
    }

    #[test]
    fn test_ip_rate_limiter() {
        let config = RateLimitConfig::new(10, 20);
        let limiter = IpRateLimiter::new(&config);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow burst
        for _ in 0..20 {
            assert!(limiter.check(ip));
        }

        // Should be rate limited after burst
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_ip_isolation() {
        let config = RateLimitConfig::new(1, 1);
        let limiter = IpRateLimiter::new(&config);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // First request from each IP should pass
        assert!(limiter.check(ip1));
        assert!(limiter.check(ip2));

        // Second request from ip1 should fail, but ip2 should still work for new IP
        assert!(!limiter.check(ip1));
    }
}

