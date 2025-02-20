//! MicroAuth - A developer-friendly authentication library
//! 
//! This library provides an embedded OAuth2 authentication server that's as easy to use
//! as an ORM. It handles all the complexities of OAuth2 and cryptography while providing
//! a clean, intuitive API.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use microauth::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     let auth = MicroAuth::new()
//!         .with_app_name("My Cool App")
//!         .persist_to("./auth.db")
//!         .init()
//!         .await?;
//!
//!     // Create a new client
//!     let client = auth.clients()
//!         .create()
//!         .name("Mobile App")
//!         .redirect_url("myapp://auth")
//!         .save()
//!         .await?;
//!
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unreachable_pub)]
#![deny(unused_crate_dependencies)]
#![deny(clippy::pedantic)]
#![warn(clippy::nursery)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::integer_arithmetic)]
#![deny(clippy::float_arithmetic)]

use async_trait as _;
use tracing_subscriber as _;
#[cfg(test)]
use {
    pretty_assertions as _,
    test_log as _,
    tokio_test as _,
    tracing_test as _,
};

mod auth;
mod client;
mod token;
mod storage;
mod crypto;
mod error;
mod logging;
mod oauth;

pub use crate::error::{Error, Result};
pub use crate::auth::{AuthUser, TokenClaims, AuthFlow};
pub use crate::client::{Client, ClientBuilder, ClientUpdateBuilder, ClientManager};
pub use crate::token::{Token, TokenManager, TokenListBuilder};
pub use crate::storage::StorageConfig;
pub use crate::logging::{Event, TokenOperation, ClientOperation, SystemOperation, LogConfig, Logger};
pub use crate::oauth::{OAuth2Flow, AuthorizationRequest, TokenRequest, TokenResponse};

use crate::storage::Storage;
use crate::crypto::CryptoManager;

use std::path::PathBuf;

/// Core authentication server type
pub struct MicroAuth {
    storage: Storage,
    crypto: CryptoManager,
    client_manager: ClientManager,
    token_manager: TokenManager,
    logger: Logger,
}

/// Builder for configuring MicroAuth
#[derive(Debug, Default)]
pub struct MicroAuthBuilder {
    app_name: Option<String>,
    storage_path: Option<PathBuf>,
    log_config: Option<LogConfig>,
    storage_config: Option<StorageConfig>,
}

impl MicroAuthBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the application name
    pub fn with_app_name(mut self, name: &str) -> Self {
        self.app_name = Some(name.to_string());
        self
    }

    /// Set the storage path
    pub fn persist_to(mut self, path: &str) -> Self {
        self.storage_path = Some(PathBuf::from(path));
        self
    }

    /// Set the logging configuration
    pub fn with_logging(mut self, config: LogConfig) -> Self {
        self.log_config = Some(config);
        self
    }

    /// Set the storage configuration
    pub fn with_storage(mut self, config: StorageConfig) -> Self {
        self.storage_config = Some(config);
        self
    }

    /// Initialize the MicroAuth instance
    pub async fn init(self) -> Result<MicroAuth> {
        let storage_path = self.storage_path.unwrap_or_else(|| PathBuf::from("auth.db"));
        let storage = Storage::new(&storage_path);
        let crypto = CryptoManager::new(vec![0; 32])?;
        let client_manager = ClientManager::new(storage.clone());
        let token_manager = TokenManager::new(crypto.clone(), storage.clone());
        
        let log_config = self.log_config.unwrap_or_default();
        let logger = Logger::new(log_config)?;

        Ok(MicroAuth {
            storage,
            crypto,
            client_manager,
            token_manager,
            logger,
        })
    }
}

impl MicroAuth {
    /// Create a new MicroAuth instance
    pub fn new() -> MicroAuthBuilder {
        MicroAuthBuilder::new()
    }

    /// Get the storage instance
    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Get the client manager
    pub fn clients(&self) -> &ClientManager {
        &self.client_manager
    }

    /// Get the token manager
    pub fn tokens(&self) -> &TokenManager {
        &self.token_manager
    }

    /// Get the logger
    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    /// Create a new authorization flow
    pub fn authorization_flow(&self) -> AuthFlow {
        AuthFlow::authorization_code(self.crypto.clone())
    }
}

impl Default for MicroAuth {
    fn default() -> Self {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
            rt.block_on(async {
                Self::new()
                    .init()
                    .await
                    .expect("Failed to initialize default MicroAuth instance")
            })
        })
    }
}

/// Prelude module containing commonly used types and traits
pub mod prelude {
    pub use crate::MicroAuth;
    pub use crate::error::Error;
    pub use crate::auth::AuthUser;
    pub use crate::client::Client;
    pub use crate::token::Token;
}

/// Adds two unsigned 64-bit integers
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {
        let auth = MicroAuth::new()
            .init()
            .await
            .expect("Failed to initialize MicroAuth");

        auth.clients()
            .create()
            .name("test")
            .redirect_url("http://localhost")
            .save()
            .await
            .expect("Failed to create client");
    }
}
