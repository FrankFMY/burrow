//! Email templates

use super::EmailMessage;

/// Email template generator
pub struct EmailTemplates {
    app_name: String,
    app_url: String,
}

impl EmailTemplates {
    pub fn new() -> Self {
        Self {
            app_name: std::env::var("APP_NAME").unwrap_or_else(|_| "Burrow VPN".to_string()),
            app_url: std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:5173".to_string()),
        }
    }

    /// Generate email verification email
    pub fn email_verification(&self, to: &str, token: &str) -> EmailMessage {
        let verification_url = format!("{}/verify-email?token={}", self.app_url, token);

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">{app_name}</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Verify Your Email Address</h2>
        <p>Welcome to {app_name}! Please verify your email address by clicking the button below.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{url}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email</a>
        </div>
        <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all; font-size: 12px;">{url}</p>
        <p style="color: #666; font-size: 14px;">This link will expire in 24 hours.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px;">If you didn't create an account with {app_name}, you can safely ignore this email.</p>
    </div>
</body>
</html>"#,
            app_name = self.app_name,
            url = verification_url
        );

        let text_body = format!(
            "Verify Your Email Address\n\n\
             Welcome to {app_name}! Please verify your email address by clicking the link below:\n\n\
             {url}\n\n\
             This link will expire in 24 hours.\n\n\
             If you didn't create an account with {app_name}, you can safely ignore this email.",
            app_name = self.app_name,
            url = verification_url
        );

        EmailMessage {
            to: to.to_string(),
            subject: format!("Verify your {} email", self.app_name),
            html_body,
            text_body,
        }
    }

    /// Generate password reset email
    pub fn password_reset(&self, to: &str, token: &str) -> EmailMessage {
        let reset_url = format!("{}/reset-password?token={}", self.app_url, token);

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">{app_name}</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Reset Your Password</h2>
        <p>We received a request to reset your password. Click the button below to create a new password.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{url}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:</p>
        <p style="background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all; font-size: 12px;">{url}</p>
        <p style="color: #666; font-size: 14px;">This link will expire in 1 hour.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
    </div>
</body>
</html>"#,
            app_name = self.app_name,
            url = reset_url
        );

        let text_body = format!(
            "Reset Your Password\n\n\
             We received a request to reset your password. Click the link below to create a new password:\n\n\
             {url}\n\n\
             This link will expire in 1 hour.\n\n\
             If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.",
            url = reset_url
        );

        EmailMessage {
            to: to.to_string(),
            subject: format!("Reset your {} password", self.app_name),
            html_body,
            text_body,
        }
    }

    /// Generate welcome email (sent after email verification)
    pub fn welcome(&self, to: &str, name: &str) -> EmailMessage {
        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to {app_name}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">{app_name}</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Welcome, {name}! 🎉</h2>
        <p>Your email has been verified and your account is now active.</p>
        <p>Here's what you can do next:</p>
        <ul style="padding-left: 20px;">
            <li>Create your first VPN network</li>
            <li>Invite team members to join</li>
            <li>Connect your devices securely</li>
        </ul>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{app_url}/networks" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Get Started</a>
        </div>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px;">Questions? Reply to this email and we'll help you out.</p>
    </div>
</body>
</html>"#,
            app_name = self.app_name,
            name = name,
            app_url = self.app_url
        );

        let text_body = format!(
            "Welcome, {name}!\n\n\
             Your email has been verified and your account is now active.\n\n\
             Here's what you can do next:\n\
             - Create your first VPN network\n\
             - Invite team members to join\n\
             - Connect your devices securely\n\n\
             Get started: {app_url}/networks\n\n\
             Questions? Reply to this email and we'll help you out.",
            name = name,
            app_url = self.app_url
        );

        EmailMessage {
            to: to.to_string(),
            subject: format!("Welcome to {}!", self.app_name),
            html_body,
            text_body,
        }
    }

    /// Generate password changed notification email
    pub fn password_changed(&self, to: &str) -> EmailMessage {
        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">{app_name}</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Your Password Has Been Changed</h2>
        <p>This is a confirmation that your password was successfully changed.</p>
        <p style="color: #666; font-size: 14px;">If you did not make this change, please contact us immediately or reset your password.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{app_url}/forgot-password" style="background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
        </div>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px;">This notification was sent for security purposes.</p>
    </div>
</body>
</html>"#,
            app_name = self.app_name,
            app_url = self.app_url
        );

        let text_body = format!(
            "Your Password Has Been Changed\n\n\
             This is a confirmation that your password was successfully changed.\n\n\
             If you did not make this change, please contact us immediately or reset your password:\n\
             {app_url}/forgot-password\n\n\
             This notification was sent for security purposes.",
            app_url = self.app_url
        );

        EmailMessage {
            to: to.to_string(),
            subject: format!("{} - Password Changed", self.app_name),
            html_body,
            text_body,
        }
    }
}

impl Default for EmailTemplates {
    fn default() -> Self {
        Self::new()
    }
}
