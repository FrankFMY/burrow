//! Email service trait and implementations

use std::future::Future;
use std::pin::Pin;

/// Email message structure
#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}

/// Email provider enum for tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EmailProvider {
    SendGrid,
    Smtp,
    Console,
}

/// Result type for email operations
pub type EmailResult<T> = Result<T, String>;

/// Email service trait
pub trait EmailService: Send + Sync {
    /// Get the provider type (for logging/debugging)
    #[allow(dead_code)]
    fn provider(&self) -> EmailProvider;

    /// Send an email
    fn send(&self, message: EmailMessage) -> Pin<Box<dyn Future<Output = EmailResult<()>> + Send + '_>>;
}

// ============================================================================
// SendGrid Implementation
// ============================================================================

pub struct SendGridService {
    api_key: String,
    from_email: String,
    from_name: String,
    client: reqwest::Client,
}

impl SendGridService {
    pub fn new(api_key: String, from_email: String, from_name: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            from_email,
            from_name,
            client,
        }
    }
}

impl EmailService for SendGridService {
    fn provider(&self) -> EmailProvider {
        EmailProvider::SendGrid
    }

    fn send(&self, message: EmailMessage) -> Pin<Box<dyn Future<Output = EmailResult<()>> + Send + '_>> {
        Box::pin(async move {
            let payload = serde_json::json!({
                "personalizations": [{
                    "to": [{"email": message.to}]
                }],
                "from": {
                    "email": self.from_email,
                    "name": self.from_name
                },
                "subject": message.subject,
                "content": [
                    {
                        "type": "text/plain",
                        "value": message.text_body
                    },
                    {
                        "type": "text/html",
                        "value": message.html_body
                    }
                ]
            });

            let response = self
                .client
                .post("https://api.sendgrid.com/v3/mail/send")
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .map_err(|e| format!("SendGrid request failed: {}", e))?;

            if response.status().is_success() {
                tracing::info!("Email sent via SendGrid to {}", message.to);
                Ok(())
            } else {
                let status = response.status();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("SendGrid error ({}): {}", status, error_text))
            }
        })
    }
}

// ============================================================================
// SMTP Implementation
// ============================================================================

pub struct SmtpService {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    from_email: String,
    from_name: String,
}

impl SmtpService {
    pub fn new(
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        from_email: String,
        from_name: String,
    ) -> Self {
        Self {
            host,
            port,
            username,
            password,
            from_email,
            from_name,
        }
    }
}

impl EmailService for SmtpService {
    fn provider(&self) -> EmailProvider {
        EmailProvider::Smtp
    }

    fn send(&self, message: EmailMessage) -> Pin<Box<dyn Future<Output = EmailResult<()>> + Send + '_>> {
        let host = self.host.clone();
        let port = self.port;
        let from_email = self.from_email.clone();
        let from_name = self.from_name.clone();
        let has_auth = self.username.is_some() && self.password.is_some();

        Box::pin(async move {
            // Note: Full SMTP implementation requires the `lettre` crate for TLS support.
            // This is a placeholder that logs the attempt.
            // For production use, either:
            // 1. Use SendGrid (recommended) - set EMAIL_PROVIDER=sendgrid
            // 2. Add the `lettre` crate for full SMTP support
            tracing::info!(
                "SMTP email sending to {} from {} <{}> via {}:{} (auth: {})",
                message.to,
                from_name,
                from_email,
                host,
                port,
                has_auth
            );

            // For development, just log the email content
            tracing::info!(
                "📧 SMTP EMAIL (Not Sent)\n\
                 To: {}\n\
                 Subject: {}\n\
                 ---\n\
                 {}",
                message.to,
                message.subject,
                message.text_body
            );

            // Return success in development mode to not block the flow
            if std::env::var("DEVELOPMENT").is_ok() {
                Ok(())
            } else {
                Err("SMTP not fully implemented. Use SendGrid (EMAIL_PROVIDER=sendgrid) or set DEVELOPMENT=1".to_string())
            }
        })
    }
}

// ============================================================================
// Console Implementation (for development/testing)
// ============================================================================

pub struct ConsoleService;

impl ConsoleService {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ConsoleService {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailService for ConsoleService {
    fn provider(&self) -> EmailProvider {
        EmailProvider::Console
    }

    fn send(&self, message: EmailMessage) -> Pin<Box<dyn Future<Output = EmailResult<()>> + Send + '_>> {
        Box::pin(async move {
            tracing::info!(
                "📧 EMAIL (Console Mode)\n\
                 To: {}\n\
                 Subject: {}\n\
                 ---\n\
                 {}",
                message.to,
                message.subject,
                message.text_body
            );
            Ok(())
        })
    }
}
