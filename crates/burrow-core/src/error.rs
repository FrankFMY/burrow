//! Error types for Burrow

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BurrowError {
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Authentication failed: {0}")]
    Auth(String),
    
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    
    #[error("Invalid configuration: {0}")]
    Config(String),
    
    #[error("WireGuard error: {0}")]
    WireGuard(String),
    
    #[error("Database error: {0}")]
    Database(String),
}

pub type Result<T> = std::result::Result<T, BurrowError>;
