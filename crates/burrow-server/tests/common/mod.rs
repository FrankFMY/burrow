//! Test utilities

use axum::{
    body::Body,
    http::Response,
    middleware,
    routing::{delete, get, post},
    Router,
};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

// Re-export server modules for tests
pub use burrow_server::{auth, auth_handlers, db, derp, handlers, state::AppState};

/// Create a test application with in-memory database
pub async fn create_test_app() -> Router {
    // Create in-memory SQLite database
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");

    // Run migrations
    db::migrate(&pool).await.expect("Failed to run migrations");

    // Create app state
    let jwt_secret = "test-secret-key-for-testing-only".to_string();
    let app_state = Arc::new(AppState::new(pool.clone(), jwt_secret));
    let derp_state = Arc::new(derp::DerpState::new(pool));

    // Public routes
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/api/auth/register", post(auth_handlers::register))
        .route("/api/auth/login", post(auth_handlers::login))
        .route("/api/register", post(handlers::register_node))
        .route("/api/nodes/{id}/heartbeat", post(handlers::heartbeat));

    // Protected routes
    let protected_routes = Router::new()
        .route("/api/auth/me", get(auth_handlers::me))
        .route("/api/auth/api-keys", get(auth_handlers::list_api_keys))
        .route("/api/auth/api-keys", post(auth_handlers::create_api_key))
        .route(
            "/api/auth/api-keys/{id}",
            delete(auth_handlers::revoke_api_key),
        )
        .route("/api/networks", get(handlers::list_networks))
        .route("/api/networks", post(handlers::create_network))
        .route("/api/networks/{id}", get(handlers::get_network))
        .route("/api/networks/{id}/nodes", get(handlers::list_nodes))
        .route("/api/networks/{id}/invite", post(handlers::create_invite))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_middleware,
        ));

    // Build router
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(app_state)
        .nest(
            "/derp",
            Router::new()
                .route("/", get(derp::derp_handler))
                .with_state(derp_state),
        )
}

async fn health() -> axum::Json<Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "burrow-server",
        "version": "test"
    }))
}

/// Extract JSON body from response
pub async fn response_body(response: Response<Body>) -> Value {
    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}
