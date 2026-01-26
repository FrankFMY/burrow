//! Application state

use sqlx::SqlitePool;
use std::sync::Arc;

use crate::ws::WsState;

pub struct AppState {
    pub db: SqlitePool,
    pub jwt_secret: String,
    pub ws: Arc<WsState>,
}

impl AppState {
    pub fn new(db: SqlitePool, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            ws: Arc::new(WsState::new()),
        }
    }
}
