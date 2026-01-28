//! Prometheus metrics for the Burrow server
//!
//! Exports metrics at /metrics endpoint in Prometheus format

use axum::{http::StatusCode, response::IntoResponse};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the metrics system
pub fn init_metrics() {
    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("Failed to install metrics recorder");

    METRICS_HANDLE.set(handle).ok();

    // Initialize gauges to 0
    gauge!("burrow_active_websocket_connections").set(0.0);
    gauge!("burrow_users_total").set(0.0);
    gauge!("burrow_networks_total").set(0.0);
    gauge!("burrow_nodes_total", "status" => "online").set(0.0);
    gauge!("burrow_nodes_total", "status" => "offline").set(0.0);
    gauge!("burrow_nodes_total", "status" => "pending").set(0.0);

    tracing::info!("Metrics system initialized");
}

/// Handler for /metrics endpoint
pub async fn metrics_handler() -> impl IntoResponse {
    match METRICS_HANDLE.get() {
        Some(handle) => {
            let metrics = handle.render();
            (StatusCode::OK, [("content-type", "text/plain; charset=utf-8")], metrics)
        }
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain; charset=utf-8")],
            "Metrics not initialized".to_string(),
        ),
    }
}

/// Record an HTTP request
#[allow(dead_code)]
pub fn record_http_request(method: &str, path: &str, status: u16, duration: std::time::Duration) {
    let status_str = status.to_string();
    counter!("burrow_http_requests_total", "method" => method.to_string(), "path" => normalize_path(path), "status" => status_str).increment(1);
    histogram!("burrow_http_request_duration_seconds", "method" => method.to_string(), "path" => normalize_path(path)).record(duration.as_secs_f64());
}

/// Normalize path for metrics (remove IDs to reduce cardinality)
#[allow(dead_code)]
fn normalize_path(path: &str) -> String {
    // Replace UUIDs and numeric IDs with placeholders
    let path = path.trim_end_matches('/');

    // Common patterns
    if path.starts_with("/api/networks/") && path.contains("/nodes") {
        return "/api/networks/{id}/nodes".to_string();
    }
    if path.starts_with("/api/networks/") && path.contains("/invite") {
        return "/api/networks/{id}/invite".to_string();
    }
    if path.starts_with("/api/networks/") {
        return "/api/networks/{id}".to_string();
    }
    if path.starts_with("/api/nodes/") && path.contains("/heartbeat") {
        return "/api/nodes/{id}/heartbeat".to_string();
    }
    if path.starts_with("/api/auth/api-keys/") {
        return "/api/auth/api-keys/{id}".to_string();
    }
    if path.starts_with("/api/admin/users/") {
        return "/api/admin/users/{id}".to_string();
    }

    path.to_string()
}

/// Record WebSocket connection change
#[allow(dead_code)]
pub fn record_ws_connection(delta: i64) {
    let current = gauge!("burrow_active_websocket_connections");
    if delta > 0 {
        current.increment(delta as f64);
    } else {
        current.decrement((-delta) as f64);
    }
}

/// Record authentication attempt
#[allow(dead_code)]
pub fn record_auth_attempt(success: bool) {
    let success_str = if success { "true" } else { "false" };
    counter!("burrow_auth_attempts_total", "success" => success_str).increment(1);
}

/// Update gauge for total users
pub fn set_users_total(count: i64) {
    gauge!("burrow_users_total").set(count as f64);
}

/// Update gauge for total networks
pub fn set_networks_total(count: i64) {
    gauge!("burrow_networks_total").set(count as f64);
}

/// Update gauge for nodes by status
pub fn set_nodes_by_status(online: i64, offline: i64, pending: i64) {
    gauge!("burrow_nodes_total", "status" => "online").set(online as f64);
    gauge!("burrow_nodes_total", "status" => "offline").set(offline as f64);
    gauge!("burrow_nodes_total", "status" => "pending").set(pending as f64);
}

/// Middleware helper to time requests
#[allow(dead_code)]
pub struct RequestTimer {
    start: Instant,
    method: String,
    path: String,
}

#[allow(dead_code)]
impl RequestTimer {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            start: Instant::now(),
            method: method.to_string(),
            path: path.to_string(),
        }
    }

    pub fn finish(self, status: u16) {
        record_http_request(&self.method, &self.path, status, self.start.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            normalize_path("/api/networks/123e4567-e89b-12d3-a456-426614174000"),
            "/api/networks/{id}"
        );
        assert_eq!(
            normalize_path("/api/networks/123/nodes"),
            "/api/networks/{id}/nodes"
        );
        assert_eq!(
            normalize_path("/api/auth/api-keys/abc123"),
            "/api/auth/api-keys/{id}"
        );
        assert_eq!(normalize_path("/health"), "/health");
    }
}
