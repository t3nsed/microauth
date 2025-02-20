//! Logging and audit trail functionality

use serde::Serialize;
use std::path::PathBuf;
use time::OffsetDateTime;
use tracing::{info, warn, error};
use tokio::io::AsyncWriteExt;

use crate::error::Result;

/// Types of events that can be logged
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Event {
    /// Authentication attempt event
    #[serde(rename = "auth_attempt")]
    AuthAttempt {
        /// Success or failure
        success: bool,
        /// Client ID that attempted auth
        client_id: String,
        /// Error message if failed
        error: Option<String>,
    },

    /// Token operation event
    #[serde(rename = "token")]
    Token {
        /// Type of token operation
        operation: TokenOperation,
        /// ID of the token
        token_id: String,
        /// ID of the client
        client_id: String,
    },

    /// Client operation event
    #[serde(rename = "client")]
    Client {
        /// Type of client operation
        operation: ClientOperation,
        /// ID of the client
        client_id: String,
    },

    /// System event
    #[serde(rename = "system")]
    System {
        /// Type of system event
        operation: SystemOperation,
        /// Additional details
        details: Option<String>,
    },
}

/// Types of token operations
#[derive(Debug, Clone, Serialize)]
pub enum TokenOperation {
    /// Token was created
    #[serde(rename = "created")]
    Created,
    /// Token was verified
    #[serde(rename = "verified")]
    Verified,
    /// Token was revoked
    #[serde(rename = "revoked")]
    Revoked,
    /// Token expired
    #[serde(rename = "expired")]
    Expired,
}

/// Types of client operations
#[derive(Debug, Clone, Serialize)]
pub enum ClientOperation {
    /// Client was created
    #[serde(rename = "created")]
    Created,
    /// Client was updated
    #[serde(rename = "updated")]
    Updated,
    /// Client was deleted
    #[serde(rename = "deleted")]
    Deleted,
}

/// Types of system operations
#[derive(Debug, Clone, Serialize)]
pub enum SystemOperation {
    /// System started
    #[serde(rename = "startup")]
    Startup,
    /// System shutdown
    #[serde(rename = "shutdown")]
    Shutdown,
    /// State was saved
    #[serde(rename = "state_saved")]
    StateSaved,
    /// Error occurred
    #[serde(rename = "error")]
    Error,
}

/// Configuration for the logger
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    /// Path to the log file
    pub path: PathBuf,
    /// Maximum size of log file before rotation (in bytes)
    pub max_size: u64,
    /// Number of rotated files to keep
    pub keep_files: usize,
}

/// Manages logging operations
#[derive(Debug)]
pub struct Logger {
    config: LogConfig,
    current_size: std::sync::atomic::AtomicU64,
}

impl Logger {
    /// Create a new logger
    pub fn new(config: LogConfig) -> Result<Self> {
        // Create log directory if it doesn't exist
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Get current log file size if it exists
        let current_size = std::fs::metadata(&config.path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(Self {
            config,
            current_size: std::sync::atomic::AtomicU64::new(current_size),
        })
    }

    /// Log an event
    pub async fn log_event(&self, event: Event) -> Result<()> {
        let timestamp = OffsetDateTime::now_utc();
        
        // Create log entry
        let entry = serde_json::json!({
            "timestamp": timestamp.unix_timestamp(),
            "event": event
        });
        
        let log_line = format!("{}\n", serde_json::to_string(&entry)?);
        let line_len = log_line.len() as u64;

        // Check if rotation is needed before writing
        let current = self.current_size.load(std::sync::atomic::Ordering::Relaxed);
        if current + line_len > self.config.max_size {
            self.rotate_logs().await?;
        }

        // Write to file
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.path)
            .await?
            .write_all(log_line.as_bytes())
            .await?;

        // Update size
        self.current_size.fetch_add(line_len, std::sync::atomic::Ordering::Relaxed);

        // Log to tracing
        match &event {
            Event::AuthAttempt { success, client_id, error } => {
                if *success {
                    info!(client_id = %client_id, "Authentication successful");
                } else {
                    warn!(
                        client_id = %client_id,
                        error = %error.as_deref().unwrap_or("unknown"),
                        "Authentication failed"
                    );
                }
            }
            Event::System { operation: SystemOperation::Error, details } => {
                error!(details = %details.as_deref().unwrap_or("unknown"), "System error");
            }
            _ => {
                info!(event_type = ?event, "Event logged");
            }
        }

        Ok(())
    }

    /// Rotate log files if needed
    pub async fn rotate_logs(&self) -> Result<()> {
        // Remove oldest log if we have reached keep_files limit
        for i in (1..=self.config.keep_files).rev() {
            let old_path = self.config.path.with_extension(format!("log.{}", i));
            let new_path = self.config.path.with_extension(format!("log.{}", i + 1));
            
            if old_path.exists() {
                if i == self.config.keep_files {
                    tokio::fs::remove_file(&old_path).await?;
                } else {
                    tokio::fs::rename(&old_path, &new_path).await?;
                }
            }
        }

        // Rotate current log to .1
        if self.config.path.exists() {
            let new_path = self.config.path.with_extension("log.1");
            tokio::fs::rename(&self.config.path, &new_path).await?;
        }

        // Reset size counter
        self.current_size.store(0, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn test_logger_creation() {
        let config = LogConfig {
            path: Path::new("test.log").to_path_buf(),
            max_size: 1024 * 1024,  // 1MB
            keep_files: 5,
        };

        let _logger = Logger::new(config);
    }
} 