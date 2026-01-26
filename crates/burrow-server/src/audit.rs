//! Audit logging for security events

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Auth events
    UserRegistered,
    UserLogin,
    UserLoginFailed,
    ApiKeyCreated,
    ApiKeyRevoked,

    // Network events
    NetworkCreated,
    NetworkDeleted,
    InviteCreated,
    InviteUsed,

    // Node events
    NodeRegistered,
    NodeOnline,
    NodeOffline,

    // Admin events
    UserRoleChanged,
    SettingsChanged,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl AuditEvent {
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type,
            user_id: None,
            user_email: None,
            target_type: None,
            target_id: None,
            ip_address: None,
            details: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_user(mut self, user_id: &str, email: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self.user_email = Some(email.to_string());
        self
    }

    pub fn with_target(mut self, target_type: &str, target_id: &str) -> Self {
        self.target_type = Some(target_type.to_string());
        self.target_id = Some(target_id.to_string());
        self
    }

    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Audit logger
pub struct AuditLogger {
    db: SqlitePool,
}

impl AuditLogger {
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }

    /// Log an audit event
    pub async fn log(&self, event: AuditEvent) -> Result<(), sqlx::Error> {
        // Also log to tracing for immediate visibility
        tracing::info!(
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            user_email = ?event.user_email,
            target = ?event.target_id,
            ip = ?event.ip_address,
            "Audit event"
        );

        sqlx::query(
            r#"
            INSERT INTO audit_log (id, event_type, user_id, user_email, target_type, target_id, ip_address, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.id.to_string())
        .bind(serde_json::to_string(&event.event_type).unwrap_or_default())
        .bind(&event.user_id)
        .bind(&event.user_email)
        .bind(&event.target_type)
        .bind(&event.target_id)
        .bind(&event.ip_address)
        .bind(event.details.map(|d| d.to_string()))
        .bind(event.created_at.to_rfc3339())
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Query audit events
    pub async fn query(
        &self,
        user_id: Option<&str>,
        event_type: Option<&str>,
        limit: i32,
    ) -> Result<Vec<AuditEvent>, sqlx::Error> {
        let mut query = String::from(
            "SELECT id, event_type, user_id, user_email, target_type, target_id, ip_address, details, created_at
             FROM audit_log WHERE 1=1",
        );

        if user_id.is_some() {
            query.push_str(" AND user_id = ?");
        }
        if event_type.is_some() {
            query.push_str(" AND event_type = ?");
        }
        query.push_str(" ORDER BY created_at DESC LIMIT ?");

        let mut q = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(&query);

        if let Some(uid) = user_id {
            q = q.bind(uid);
        }
        if let Some(et) = event_type {
            q = q.bind(et);
        }
        q = q.bind(limit);

        let rows = q.fetch_all(&self.db).await?;

        let events = rows
            .into_iter()
            .filter_map(|row| {
                Some(AuditEvent {
                    id: row.0.parse().ok()?,
                    event_type: serde_json::from_str(&row.1).ok()?,
                    user_id: row.2,
                    user_email: row.3,
                    target_type: row.4,
                    target_id: row.5,
                    ip_address: row.6,
                    details: row.7.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: row.8.parse().ok()?,
                })
            })
            .collect();

        Ok(events)
    }
}

/// Log convenience function
pub async fn log_event(db: &SqlitePool, event: AuditEvent) {
    let logger = AuditLogger::new(db.clone());
    if let Err(e) = logger.log(event).await {
        tracing::error!("Failed to write audit log: {}", e);
    }
}
