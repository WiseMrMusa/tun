//! Rate limiting middleware for tunnel server.
//!
//! Provides IP-based rate limiting for both the control plane and proxy endpoints
//! using the governor crate with Tower integration. Includes LRU-based cleanup
//! to bound memory usage.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response, StatusCode},
};
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
}

impl RateLimitLayer {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            limiter: Arc::new(IpRateLimiter::new(config)),
        }
    }

    pub fn from_limiter(limiter: Arc<IpRateLimiter>) -> Self {
        Self { limiter }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

/// Tower Service for rate limiting.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: Arc<IpRateLimiter>,
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
        // Try to extract IP from ConnectInfo or headers
        let ip = extract_client_ip(&req);

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

/// Extract client IP from request.
/// Checks X-Forwarded-For header first (for proxied requests), then falls back to connection info.
fn extract_client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    // Check X-Forwarded-For header (common when behind a proxy)
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            // Take the first IP in the list (original client)
            if let Some(ip_str) = value.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header (nginx)
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Fall back to connection info
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

/// Create a 429 Too Many Requests response.
fn rate_limit_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Content-Type", "text/plain")
        .header("Retry-After", "1")
        .body(Body::from("Rate limit exceeded. Please slow down."))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal error"))
                .unwrap()
        })
}

/// Create a shared rate limiter that can be used across multiple services.
pub fn create_shared_limiter(config: &RateLimitConfig) -> Arc<IpRateLimiter> {
    Arc::new(IpRateLimiter::new(config))
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

