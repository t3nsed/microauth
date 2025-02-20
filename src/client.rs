//! Client management functionality

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use std::sync::Arc;
use tokio::sync::RwLock;
use nanoid::nanoid;

use crate::error::{Error, Result};
use crate::storage::Storage;

/// Represents an OAuth client application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    /// Unique identifier for the client
    pub id: String,
    
    /// Name of the client application
    pub name: String,
    
    /// Redirect URL for OAuth flow
    pub redirect_url: String,
    
    /// When the client was created
    pub created_at: OffsetDateTime,
    
    /// List of allowed scopes
    pub allowed_scopes: Vec<String>,
}

impl Client {
    /// Create a new client with the given parameters
    pub fn new(
        id: String,
        name: String,
        redirect_url: String,
        allowed_scopes: Vec<String>,
    ) -> Self {
        Self {
            id,
            name,
            redirect_url,
            created_at: OffsetDateTime::now_utc(),
            allowed_scopes,
        }
    }
}

/// Builder for creating new clients
#[derive(Debug)]
pub struct ClientBuilder {
    name: Option<String>,
    redirect_url: Option<String>,
    allowed_scopes: Vec<String>,
    storage: Arc<RwLock<Storage>>,
}

impl ClientBuilder {
    fn new(storage: Arc<RwLock<Storage>>) -> Self {
        Self {
            name: None,
            redirect_url: None,
            allowed_scopes: Vec::new(),
            storage,
        }
    }

    /// Set the client name
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set the redirect URL
    pub fn redirect_url(mut self, url: &str) -> Self {
        self.redirect_url = Some(url.to_string());
        self
    }

    /// Add allowed scopes
    pub fn allowed_scopes(mut self, scopes: &[&str]) -> Self {
        self.allowed_scopes = scopes.iter().map(ToString::to_string).collect();
        self
    }

    /// Create the client
    pub async fn save(self) -> Result<Client> {
        let name = self.name.ok_or_else(|| Error::Client("Client name is required".into()))?;
        let redirect_url = self.redirect_url.ok_or_else(|| Error::Client("Redirect URL is required".into()))?;

        // Generate client ID
        let client_id = nanoid!();

        let client = Client::new(
            client_id,
            name,
            redirect_url,
            self.allowed_scopes,
        );

        // Store the client
        let storage = self.storage.write().await;
        storage.add_client(client.clone()).await?;
        storage.save().await?;

        Ok(client)
    }
}

/// Builder for updating existing clients
#[derive(Debug)]
pub struct ClientUpdateBuilder {
    client_id: String,
    name: Option<String>,
    redirect_url: Option<String>,
    storage: Arc<RwLock<Storage>>,
}

impl ClientUpdateBuilder {
    fn new(client_id: &str, storage: Arc<RwLock<Storage>>) -> Self {
        Self {
            client_id: client_id.to_string(),
            name: None,
            redirect_url: None,
            storage,
        }
    }

    /// Update the client name
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Update the redirect URL
    pub fn redirect_url(mut self, url: &str) -> Self {
        self.redirect_url = Some(url.to_string());
        self
    }

    /// Save the updates
    pub async fn save(self) -> Result<Client> {
        let mut storage = self.storage.write().await;
        
        // Get existing client
        let mut client = storage.get_client(&self.client_id).await?;
        
        // Update fields
        if let Some(name) = self.name {
            client.name = name;
        }
        if let Some(redirect_url) = self.redirect_url {
            client.redirect_url = redirect_url;
        }

        // Save changes
        storage.update_client(client.clone()).await?;
        storage.save().await?;

        Ok(client)
    }
}

/// Manager for client operations
#[derive(Debug)]
pub struct ClientManager {
    storage: Arc<RwLock<Storage>>,
}

impl ClientManager {
    /// Create a new client manager
    pub fn new(storage: Storage) -> Self {
        Self {
            storage: Arc::new(RwLock::new(storage)),
        }
    }

    /// Start creating a new client
    pub fn create(&self) -> ClientBuilder {
        ClientBuilder::new(Arc::clone(&self.storage))
    }

    /// Start updating an existing client
    pub fn update(&self, client_id: &str) -> ClientUpdateBuilder {
        ClientUpdateBuilder::new(client_id, Arc::clone(&self.storage))
    }

    /// Delete a client
    pub async fn delete(&self, client_id: &str) -> Result<()> {
        let mut storage = self.storage.write().await;
        storage.remove_client(client_id).await?;
        storage.save().await?;
        Ok(())
    }

    /// List all clients
    pub async fn list(&self) -> Result<Vec<Client>> {
        let storage = self.storage.read().await;
        storage.get_clients().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_lifecycle() {
        let storage = Storage::new_in_memory();
        let manager = ClientManager::new(storage);

        // Create client
        let client = manager.create()
            .name("Test Client")
            .redirect_url("https://example.com/callback")
            .allowed_scopes(&["read", "write"])
            .save()
            .await
            .unwrap();

        assert_eq!(client.name, "Test Client");

        // Update client
        let updated = manager.update(&client.id)
            .name("Updated Client")
            .save()
            .await
            .unwrap();

        assert_eq!(updated.name, "Updated Client");
        assert_eq!(updated.redirect_url, client.redirect_url);

        // List clients
        let clients = manager.list().await.unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, client.id);

        // Delete client
        manager.delete(&client.id).await.unwrap();
        let clients = manager.list().await.unwrap();
        assert!(clients.is_empty());
    }
} 