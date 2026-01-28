//! Email service module
//!
//! Provides abstraction over email providers (SendGrid, SMTP, Console for testing)

mod service;
mod templates;

pub use service::{EmailMessage, EmailProvider, EmailService};
pub use templates::EmailTemplates;

/// Create email service based on configuration
pub fn create_email_service() -> Box<dyn EmailService> {
    let provider = std::env::var("EMAIL_PROVIDER")
        .unwrap_or_else(|_| "console".to_string())
        .to_lowercase();

    match provider.as_str() {
        "sendgrid" => {
            let api_key = std::env::var("SENDGRID_API_KEY")
                .expect("SENDGRID_API_KEY must be set when EMAIL_PROVIDER=sendgrid");
            let from_email = std::env::var("EMAIL_FROM")
                .unwrap_or_else(|_| "noreply@burrow.dev".to_string());
            let from_name = std::env::var("EMAIL_FROM_NAME")
                .unwrap_or_else(|_| "Burrow VPN".to_string());

            Box::new(service::SendGridService::new(api_key, from_email, from_name))
        }
        "smtp" => {
            let host = std::env::var("SMTP_HOST")
                .expect("SMTP_HOST must be set when EMAIL_PROVIDER=smtp");
            let port: u16 = std::env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .expect("Invalid SMTP_PORT");
            let username = std::env::var("SMTP_USER").ok();
            let password = std::env::var("SMTP_PASSWORD").ok();
            let from_email = std::env::var("EMAIL_FROM")
                .unwrap_or_else(|_| "noreply@burrow.dev".to_string());
            let from_name = std::env::var("EMAIL_FROM_NAME")
                .unwrap_or_else(|_| "Burrow VPN".to_string());

            Box::new(service::SmtpService::new(
                host, port, username, password, from_email, from_name,
            ))
        }
        _ => {
            tracing::info!("Using console email provider (emails will be logged, not sent)");
            Box::new(service::ConsoleService::new())
        }
    }
}
