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
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::state::AppState;

/// Rate limiter configuration
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_WINDOW: u32 = 60; // 60 requests per minute
const AUTH_MAX_REQUESTS: u32 = 10; // 10 auth attempts per minute

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

fn extract_client_ip(request: &Request) -> IpAddr {
    // Try X-Forwarded-For header first (for reverse proxies)
    if let Some(xff) = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
    {
        if let Some(ip) = xff.split(',').next().and_then(|s| s.trim().parse().ok()) {
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

    // Fallback to localhost
    "127.0.0.1".parse().unwrap()
}
