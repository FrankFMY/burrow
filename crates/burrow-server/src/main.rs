//! Burrow Coordination Server
//!
//! Manages node registration, key exchange, and network coordination

use anyhow::Result;
use axum::{
    extract::State,
    http::{header, Method, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod admin_handlers;
mod audit;
mod auth;
mod auth_handlers;
mod db;
mod derp;
mod email;
mod handlers;
mod lockout;
mod password_check;
mod rate_limit;
mod state;
mod totp;
mod ws;

use derp::DerpState;
use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "burrow_server=debug,info".into()),
        ))
        .init();

    tracing::info!("🕳️  Starting Burrow coordination server...");

    // Initialize database
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:burrow.db?mode=rwc".to_string());
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Run migrations
    db::migrate(&pool).await?;
    
    tracing::info!("✓ Database initialized");

    // JWT secret (use cryptographically secure RNG)
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| {
            tracing::warn!("JWT_SECRET not set, using random secret (sessions will not persist across restarts)");
            use rand::{Rng, SeedableRng};
            use rand_chacha::ChaCha20Rng;
            let mut rng = ChaCha20Rng::from_entropy();
            (0..64)
                .map(|_| {
                    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                    let idx = rng.gen_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect()
        });

    // Create app state
    let cleanup_pool = pool.clone();
    let app_state = Arc::new(AppState::new(pool.clone(), jwt_secret));
    let derp_state = Arc::new(DerpState::new(pool));

    // Initialize server start time for uptime tracking
    admin_handlers::init_server_start_time();

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/api/auth/register", post(auth_handlers::register))
        .route("/api/auth/login", post(auth_handlers::login))
        .route("/api/auth/verify-email", post(auth_handlers::verify_email))
        .route("/api/auth/resend-verification", post(auth_handlers::resend_verification))
        .route("/api/auth/forgot-password", post(auth_handlers::forgot_password))
        .route("/api/auth/reset-password", post(auth_handlers::reset_password))
        .route("/api/auth/refresh", post(auth_handlers::refresh_token))
        .route("/api/register", post(handlers::register_node))
        .route("/api/nodes/{id}/heartbeat", post(handlers::heartbeat))
        // WebSocket for real-time updates
        .route("/ws", get(ws::ws_handler));

    // Protected routes (require auth)
    let protected_routes = Router::new()
        .route("/api/auth/me", get(auth_handlers::me))
        .route("/api/auth/logout", post(auth_handlers::logout))
        .route("/api/auth/api-keys", get(auth_handlers::list_api_keys))
        .route("/api/auth/api-keys", post(auth_handlers::create_api_key))
        .route("/api/auth/api-keys/{id}", delete(auth_handlers::revoke_api_key))
        // Email verification status (requires auth)
        .route("/api/auth/email-status", get(auth_handlers::email_verification_status))
        // 2FA routes
        .route("/api/auth/totp", get(auth_handlers::totp_status))
        .route("/api/auth/totp/enable", post(auth_handlers::enable_totp))
        .route("/api/auth/totp/verify", post(auth_handlers::verify_totp_setup))
        .route("/api/auth/totp/disable", post(auth_handlers::disable_totp))
        // Network routes
        .route("/api/networks", get(handlers::list_networks))
        .route("/api/networks", post(handlers::create_network))
        .route("/api/networks/{id}", get(handlers::get_network))
        .route("/api/networks/{id}", delete(handlers::delete_network))
        .route("/api/networks/{id}/nodes", get(handlers::list_nodes))
        .route("/api/networks/{id}/invite", post(handlers::create_invite))
        // Admin routes (role check inside handlers)
        .route("/api/admin/users", get(admin_handlers::list_users))
        .route("/api/admin/users/{id}", get(admin_handlers::get_user))
        .route("/api/admin/users/{id}", axum::routing::put(admin_handlers::update_user))
        .route("/api/admin/users/{id}", delete(admin_handlers::delete_user))
        .route("/api/admin/networks", get(admin_handlers::list_all_networks))
        .route("/api/admin/stats", get(admin_handlers::get_stats))
        .route("/api/admin/audit-log", get(admin_handlers::list_audit_log))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_middleware,
        ));

    // Configure CORS
    let cors = if std::env::var("CORS_ALLOW_ALL").unwrap_or_default() == "true" {
        CorsLayer::permissive()
    } else {
        let allowed_origins = std::env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173,http://localhost:3000".to_string());

        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
            .allow_credentials(true) // Allow httpOnly cookies to be sent
            .allow_origin(
                allowed_origins
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect::<Vec<_>>(),
            )
    };

    // Build router
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(app_state.clone())
        // DERP relay endpoint (separate state)
        .nest(
            "/derp",
            Router::new()
                .route("/", get(derp::derp_handler))
                .with_state(derp_state),
        )
        // Rate limiting on auth endpoints
        .layer(axum::middleware::from_fn_with_state(
            app_state,
            rate_limit::rate_limit_middleware,
        ))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        // Security headers
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        ))
        // HSTS: Force HTTPS for 1 year including subdomains
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));

    // Start background cleanup task for rate limiter
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval.tick().await;
            rate_limit::get_rate_limiter().cleanup().await;
            tracing::debug!("Rate limiter cleanup completed");
        }
    });

    // Start background cleanup task for login attempts
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
        loop {
            interval.tick().await;
            match lockout::cleanup_old_attempts(&cleanup_pool).await {
                Ok(count) => tracing::debug!("Cleaned up {} old login attempts", count),
                Err(e) => tracing::error!("Failed to cleanup login attempts: {}", e),
            }
        }
    });

    // Start server
    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Check database connectivity
    let db_ok = sqlx::query("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    let status = if db_ok { "ok" } else { "degraded" };
    let status_code = if db_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };

    (
        status_code,
        Json(serde_json::json!({
            "status": status,
            "service": "burrow-server",
            "version": env!("CARGO_PKG_VERSION"),
            "database": if db_ok { "connected" } else { "disconnected" }
        })),
    )
}
