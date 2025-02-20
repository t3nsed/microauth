//! Error types for the MicroAuth library

use thiserror::Error;

/// Main error type for the library
#[derive(Error, Debug)]
pub enum Error {
    /// Authentication-related errors
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Client-related errors
    #[error("Client error: {0}")]
    Client(String),

    /// Token-related errors
    #[error("Token error: {0}")]
    Token(String),

    /// Storage-related errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// Cryptography-related errors
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type alias for the library
pub type Result<T> = std::result::Result<T, Error>; 