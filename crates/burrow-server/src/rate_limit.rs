//! Simple in-memory rate limiting

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::state::AppState;

/// Rate limiter configuration
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_WINDOW: u32 = 120; // 120 requests per minute
const AUTH_MAX_REQUESTS: u32 = 30; // 30 auth attempts per minute (higher for dev)
const REGISTRATION_MAX_REQUESTS: u32 = 10; // 10 node registrations per minute per IP
const HEARTBEAT_MAX_REQUESTS: u32 = 120; // 120 heartbeats per minute (2 per second is reasonable)
const MAX_BUCKETS: usize = 100_000; // Maximum tracked IPs to prevent memory exhaustion

/// Rate limit state stored in app state
#[derive(Default)]
pub struct RateLimitState {
    buckets: RwLock<HashMap<IpAddr, RateBucket>>,
}

struct RateBucket {
    count: u32,
    window_start: Instant,
}

impl RateLimitState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn check_and_increment(&self, ip: IpAddr, limit: u32) -> bool {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        // Prevent memory exhaustion - if too many buckets, cleanup expired first
        if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(&ip) {
            buckets.retain(|_, bucket| now.duration_since(bucket.window_start) <= RATE_LIMIT_WINDOW);

            // If still at limit after cleanup, reject new IPs
            if buckets.len() >= MAX_BUCKETS {
                tracing::warn!("Rate limiter at capacity ({} buckets), rejecting new IP", MAX_BUCKETS);
                return false;
            }
        }

        let bucket = buckets.entry(ip).or_insert(RateBucket {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(bucket.window_start) > RATE_LIMIT_WINDOW {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if bucket.count >= limit {
            return false;
        }

        bucket.count += 1;
        true
    }

    /// Cleanup old entries periodically
    pub async fn cleanup(&self) {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        buckets.retain(|_, bucket| now.duration_since(bucket.window_start) <= RATE_LIMIT_WINDOW * 2);
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // Extract client IP from headers or connection
    let ip = extract_client_ip(&request);

    // Determine rate limit based on path
    let path = request.uri().path();
    let limit = if path.contains("/auth/") {
        AUTH_MAX_REQUESTS
    } else if path == "/api/register" {
        REGISTRATION_MAX_REQUESTS
    } else if path.contains("/heartbeat") {
        HEARTBEAT_MAX_REQUESTS
    } else {
        MAX_REQUESTS_PER_WINDOW
    };

    // Use global rate limiter
    let limiter = get_rate_limiter();

    if !limiter.check_and_increment(ip, limit).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "Too many requests",
                "retry_after": RATE_LIMIT_WINDOW.as_secs()
            })),
        )
            .into_response();
    }

    next.run(request).await
}

/// Get the global rate limiter for cleanup
pub fn get_rate_limiter() -> &'static RateLimitState {
    static RATE_LIMITER: std::sync::OnceLock<RateLimitState> = std::sync::OnceLock::new();
    RATE_LIMITER.get_or_init(RateLimitState::new)
}

pub fn extract_client_ip(request: &Request) -> IpAddr {
    // SECURITY: Only trust proxy headers if TRUST_PROXY env var is set
    // This prevents IP spoofing attacks where attackers set X-Forwarded-For
    // to bypass rate limiting
    let trust_proxy = std::env::var("TRUST_PROXY").unwrap_or_default() == "true";

    if trust_proxy {
        // Try X-Forwarded-For header (for reverse proxies)
        // Only the LAST IP is trustworthy (added by our reverse proxy)
        // Earlier IPs can be spoofed by the client
        if let Some(xff) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
        {
            // Take the LAST IP (most recently added by trusted proxy)
            // NOT the first (which can be spoofed)
            if let Some(ip) = xff.split(',').next_back().and_then(|s| s.trim().parse().ok()) {
                return ip;
            }
        }

        // Try X-Real-IP header
        if let Some(xri) = request
            .headers()
            .get("x-real-ip")
            .and_then(|h| h.to_str().ok())
        {
            if let Ok(ip) = xri.parse() {
                return ip;
            }
        }
    }

    // Try to get real connection IP from extensions (if available)
    // This would be set by the server framework from the actual TCP connection
    if let Some(connect_info) = request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        return connect_info.0.ip();
    }

    // Fallback to localhost (safe default - will rate limit all unknown sources together)
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}
