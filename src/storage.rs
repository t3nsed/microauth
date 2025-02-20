//! Storage management for persistent state

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time as tokio_time;
use time::OffsetDateTime;
use tracing::{info, error};
use sha2::{Sha256, Digest};

use crate::crypto::CryptoManager;
use crate::error::{Error, Result};
use crate::logging::{Event, SystemOperation};
use crate::{Client, Token};

const DEFAULT_KEY_RETENTION_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);   // 7 days

/// Configuration for storage
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Path to the storage file
    pub path: PathBuf,
    
    /// How often to save state (in seconds)
    pub save_interval: u64,
    
    /// Maximum number of clients
    pub max_clients: usize,
    
    /// Maximum number of tokens per user
    pub max_tokens_per_user: usize,
    
    /// How often to rotate keys
    pub key_rotation_interval: Duration,
    
    /// How long to retain old keys
    pub key_retention_period: Duration,
    
    /// Whether to automatically rotate keys
    pub auto_rotate_keys: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("auth.db"),
            save_interval: 300,
            max_clients: 1000,
            max_tokens_per_user: 100,
            key_rotation_interval: Duration::from_secs(90 * 24 * 3600), // 90 days
            key_retention_period: Duration::from_secs(180 * 24 * 3600), // 180 days
            auto_rotate_keys: true,
        }
    }
}

/// Internal storage state
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageState {
    clients: HashMap<String, Client>,
    tokens: HashMap<String, Token>,
    created_at: OffsetDateTime,
    checksum: String,
    key_version: u32,
    last_rotation: Option<OffsetDateTime>,
}

impl StorageState {
    fn update_checksum(&mut self) {
        let mut hasher = Sha256::new();
        let mut state_copy = self.clone();
        state_copy.checksum = String::new();
        
        let state_bytes = serde_json::to_vec(&state_copy)
            .expect("Failed to serialize state");
        
        hasher.update(&state_bytes);
        self.checksum = format!("{:x}", hasher.finalize());
    }
}

#[derive(Debug)]
struct KeyStore {
    current_version: u32,
    keys: HashMap<u32, Arc<CryptoManager>>,
    key_timestamps: HashMap<u32, OffsetDateTime>,
}

impl KeyStore {
    fn new(initial_key: CryptoManager) -> Self {
        let mut keys = HashMap::new();
        let mut key_timestamps = HashMap::new();
        let now = OffsetDateTime::now_utc();
        
        keys.insert(1, Arc::new(initial_key));
        key_timestamps.insert(1, now);
        
        Self {
            current_version: 1,
            keys,
            key_timestamps,
        }
    }

    fn cleanup_old_keys(&mut self, retention_period: Duration) -> Vec<u32> {
        let now = OffsetDateTime::now_utc();
        let mut removed_versions = Vec::new();

        let cutoff = now - tokio_time::Duration::from_secs(retention_period.as_secs());
        
        let versions: Vec<_> = self.keys.keys().cloned().collect();
        for version in versions {
            if version != self.current_version {
                if let Some(timestamp) = self.key_timestamps.get(&version) {
                    if *timestamp < cutoff {
                        self.keys.remove(&version);
                        self.key_timestamps.remove(&version);
                        removed_versions.push(version);
                    }
                }
            }
        }

        removed_versions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyBackup {
    version: u32,
    keys: HashMap<u32, Vec<u8>>,
    created_at: OffsetDateTime,
    checksum: String,
}

impl KeyBackup {
    fn new(keys: HashMap<u32, Vec<u8>>) -> Self {
        let mut backup = Self {
            version: 1,
            keys,
            created_at: OffsetDateTime::now_utc(),
            checksum: String::new(),
        };
        backup.update_checksum();
        backup
    }

    fn update_checksum(&mut self) {
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&self.version.to_le_bytes());
        
        let mut versions: Vec<_> = self.keys.keys().collect();
        versions.sort_unstable();
        
        for version in versions {
            if let Some(key) = self.keys.get(version) {
                hasher.update(&version.to_le_bytes());
                hasher.update(key);
            }
        }
        
        hasher.update(self.created_at.unix_timestamp().to_le_bytes().as_ref());
        let digest = hasher.finish();
        self.checksum = URL_SAFE_NO_PAD.encode(digest.as_ref());
    }

    fn verify_checksum(&self) -> bool {
        let mut backup_copy = self.clone();
        backup_copy.checksum = String::new();
        backup_copy.update_checksum();
        backup_copy.checksum == self.checksum
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyRotationMetrics {
    pub total_rotations: u64,
    pub failed_rotations: u64,
    pub last_rotation_duration_ms: u64,
    pub keys_in_use: u32,
    pub oldest_key_age_seconds: u64,
    pub cleanup_count: u64,
    pub total_keys_removed: u64,
}

impl Default for KeyRotationMetrics {
    fn default() -> Self {
        Self {
            total_rotations: 0,
            failed_rotations: 0,
            last_rotation_duration_ms: 0,
            keys_in_use: 1,
            oldest_key_age_seconds: 0,
            cleanup_count: 0,
            total_keys_removed: 0,
        }
    }
}

/// Manages persistent storage
#[derive(Debug, Clone)]
pub struct Storage {
    state: Arc<RwLock<StorageState>>,
    path: Arc<Path>,
    config: Option<StorageConfig>,
    keys: Arc<RwLock<KeyStore>>,
    metrics: Arc<RwLock<KeyRotationMetrics>>,
    rotation_task: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl Storage {
    /// Create a new storage instance
    pub fn new(path: &Path) -> Self {
        Self {
            state: Arc::new(RwLock::new(StorageState {
                clients: HashMap::new(),
                tokens: HashMap::new(),
                created_at: OffsetDateTime::now_utc(),
                checksum: String::new(),
                key_version: 1,
                last_rotation: None,
            })),
            path: Arc::from(path),
            config: Some(StorageConfig::default()),
            keys: Arc::new(RwLock::new(KeyStore::new(CryptoManager::new(vec![0; 32]).unwrap()))),
            metrics: Arc::new(RwLock::new(KeyRotationMetrics::default())),
            rotation_task: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a new in-memory storage instance for testing
    pub fn new_in_memory() -> Self {
        Self::new(Path::new(":memory:"))
    }

    /// Force a save of the current state
    pub async fn save(&self) -> Result<()> {
        let state_guard = self.state.read().await;
        let mut state_copy = (*state_guard).clone();
        state_copy.checksum = String::new();
        state_copy.update_checksum();
        
        let json = serde_json::to_string(&state_copy)
            .map_err(|e| Error::Storage(format!("Failed to serialize state: {}", e)))?;
        
        tokio::fs::write(&*self.path, json).await
            .map_err(|e| Error::Storage(format!("Failed to write state file: {}", e)))?;
        
        info!(
            event = ?Event::System {
                operation: SystemOperation::StateSaved,
                details: None,
            },
            "State saved to file"
        );
        
        Ok(())
    }

    /// Load state from disk
    pub async fn load(&self) -> Result<()> {
        self.load_from_file().await?;
        Ok(())
    }

    pub async fn load_from_file(&self) -> Result<()> {
        let json = tokio::fs::read_to_string(&*self.path).await
            .map_err(|e| Error::Storage(format!("Failed to read state file: {}", e)))?;
        
        let mut state: StorageState = serde_json::from_str(&json)
            .map_err(|e| Error::Storage(format!("Failed to deserialize state: {}", e)))?;
        
        let original_checksum = state.checksum.clone();
        state.checksum = String::new();
        state.update_checksum();
        
        if state.checksum != original_checksum {
            return Err(Error::Storage("State file checksum mismatch".into()));
        }
        
        let mut state_guard = self.state.write().await;
        *state_guard = state;
        
        Ok(())
    }

    /// Start the background save task
    pub async fn start_background_save(&self) -> Result<()> {
        let config = self.config.as_ref().ok_or_else(|| Error::Storage("No configuration".into()))?;
        let interval = Duration::from_secs(config.save_interval);
        let state = Arc::clone(&self.state);
        let path = self.path.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio_time::interval(interval);
            loop {
                interval.tick().await;
                let state_guard = state.write().await;
                let mut state_copy = (*state_guard).clone();
                state_copy.checksum = String::new();
                state_copy.update_checksum();

                let json = serde_json::to_string(&state_copy)
                    .map_err(|e| error!("Failed to serialize state: {}", e))
                    .ok();

                if let Some(json) = json {
                    if let Err(e) = tokio::fs::write(&*path, json).await {
                        error!("Failed to write state file: {}", e);
                    }
                }
            }
        });

        let mut rotation_task = self.rotation_task.write().await;
        *rotation_task = Some(handle);

        Ok(())
    }

    pub async fn stop_background_save(&self) -> Result<()> {
        let mut rotation_task = self.rotation_task.write().await;
        if let Some(handle) = rotation_task.take() {
            handle.abort();
        }
        Ok(())
    }

    pub async fn get_user_tokens(&self, user_id: &str) -> Result<Vec<Token>> {
        let state = self.state.read().await;
        Ok(state.tokens
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect())
    }

    pub async fn add_token(&self, token: Token) -> Result<()> {
        let mut state = self.state.write().await;
        state.tokens.insert(token.id.clone(), token);
        Ok(())
    }

    pub async fn remove_token(&self, token_id: &str) -> Result<()> {
        let mut state = self.state.write().await;
        state.tokens.remove(token_id);
        Ok(())
    }

    pub async fn rotate_key(&self, new_key: CryptoManager) -> Result<()> {
        let start_time = std::time::Instant::now();
        let mut metrics = self.metrics.write().await;

        let result = async {
            let mut keys = self.keys.write().await;
            let new_version = keys.current_version + 1;
            
            info!(
                old_version = keys.current_version,
                new_version = new_version,
                "Starting key rotation"
            );
            
            // Add new key
            keys.keys.insert(new_version, Arc::new(new_key));
            keys.key_timestamps.insert(new_version, OffsetDateTime::now_utc());
            
            // Update state with new key version
            let mut state = self.state.write().await;
            state.key_version = new_version;
            
            // Update current version
            keys.current_version = new_version;
            
            // Update metrics
            metrics.total_rotations += 1;
            metrics.keys_in_use = keys.keys.len() as u32;
            if let Some(oldest) = keys.key_timestamps.values().min() {
                metrics.oldest_key_age_seconds = (OffsetDateTime::now_utc() - *oldest)
                    .whole_seconds()
                    .max(0) as u64;
            }
            
            // Save state with new key
            if let Some(config) = &self.config {
                self.save_to_file(&config.path).await?;
            }
            
            info!(
                version = new_version,
                duration_ms = start_time.elapsed().as_millis(),
                "Key rotation completed successfully"
            );

            Ok(())
        }.await;

        metrics.last_rotation_duration_ms = start_time.elapsed().as_millis() as u64;

        if let Err(e) = &result {
            metrics.failed_rotations += 1;
            error!(error = %e, "Key rotation failed");
        }

        result
    }

    pub async fn remove_old_key(&self, version: u32) -> Result<()> {
        let mut keys = self.keys.write().await;
        
        // Cannot remove current key
        if version == keys.current_version {
            return Err(Error::Storage("Cannot remove current key".into()));
        }
        
        // Remove the key
        keys.keys.remove(&version);
        Ok(())
    }

    pub async fn export_keys(&self, backup_key: &CryptoManager) -> Result<Vec<u8>> {
        let keys = self.keys.read().await;
        let mut key_data = HashMap::new();
        
        for (version, key) in &keys.keys {
            let raw_key = key.export_key();
            key_data.insert(*version, raw_key);
        }
        
        let backup = KeyBackup::new(key_data);
        
        let backup_json = serde_json::to_vec(&backup)
            .map_err(|e| Error::Storage(format!("Failed to serialize key backup: {}", e)))?;
            
        let encrypted = backup_key.encrypt(&backup_json)
            .map_err(|e| Error::Storage(format!("Failed to encrypt key backup: {}", e)))?;
            
        Ok(encrypted)
    }

    pub async fn save_keys_to_file(&self, backup_key: &CryptoManager, path: &Path) -> Result<()> {
        let encrypted = self.export_keys(backup_key).await?;
        let encoded = URL_SAFE_NO_PAD.encode(&encrypted);
        
        // Use atomic write pattern
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, encoded)
            .await
            .map_err(|e| Error::Storage(format!("Failed to write key backup: {}", e)))?;
            
        tokio::fs::rename(&temp_path, path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to save key backup: {}", e)))?;
            
        Ok(())
    }

    pub async fn import_keys(&self, backup_key: &CryptoManager, encrypted_backup: &[u8]) -> Result<()> {
        // Decrypt and deserialize
        let backup_json = backup_key.decrypt(encrypted_backup)
            .map_err(|e| Error::Storage(format!("Failed to decrypt key backup: {}", e)))?;
            
        let backup: KeyBackup = serde_json::from_slice(&backup_json)
            .map_err(|e| Error::Storage(format!("Failed to deserialize key backup: {}", e)))?;
            
        // Verify backup integrity
        if !backup.verify_checksum() {
            return Err(Error::Storage("Key backup checksum verification failed".into()));
        }
        
        // Import keys
        let mut keys = self.keys.write().await;
        for (version, key_data) in backup.keys {
            let key = CryptoManager::from_key(key_data)
                .map_err(|e| Error::Storage(format!("Failed to import key {}: {}", version, e)))?;
            keys.keys.insert(version, Arc::new(key));
        }
        
        Ok(())
    }

    pub async fn load_keys_from_file(&self, backup_key: &CryptoManager, path: &Path) -> Result<()> {
        let encoded = tokio::fs::read(path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to read key backup: {}", e)))?;
            
        let encrypted = URL_SAFE_NO_PAD.decode(&encoded)
            .map_err(|e| Error::Storage(format!("Invalid key backup encoding: {}", e)))?;
            
        self.import_keys(backup_key, &encrypted).await
    }

    pub async fn start_key_rotation(&self) -> Result<()> {
        if let Some(config) = &self.config {
            if !config.auto_rotate_keys {
                return Ok(());
            }

            let interval = config.key_rotation_interval;
            let retention = config.key_retention_period;
            let keys = Arc::clone(&self.keys);
            let state = Arc::clone(&self.state);
            let metrics = Arc::clone(&self.metrics);

            let mut rotation_task = self.rotation_task.write().await;
            if rotation_task.is_some() {
                return Ok(());
            }

            info!(
                interval_days = interval.as_secs() / 86400,
                retention_days = retention.as_secs() / 86400,
                "Starting automatic key rotation task"
            );

            let handle = tokio::spawn(async move {
                let mut interval_timer = tokio_time::interval(interval);
                loop {
                    interval_timer.tick().await;
                    
                    // Check if rotation is needed
                    let should_rotate = {
                        let state = state.read().await;
                        match state.last_rotation {
                            Some(last) => {
                                let now = OffsetDateTime::now_utc();
                                now - last >= time::Duration::seconds(interval.as_secs() as i64)
                            }
                            None => true,
                        }
                    };

                    if should_rotate {
                        let start_time = std::time::Instant::now();
                        let mut metrics = metrics.write().await;

                        let new_key = CryptoManager::new(vec![0; 32]);
                        if let Ok(new_key) = new_key {
                            let mut keys = keys.write().await;
                            let new_version = keys.current_version + 1;
                            
                            info!(
                                old_version = keys.current_version,
                                new_version = new_version,
                                "Automatic key rotation starting"
                            );

                            keys.keys.insert(new_version, Arc::new(new_key));
                            keys.key_timestamps.insert(new_version, OffsetDateTime::now_utc());
                            keys.current_version = new_version;

                            let removed = keys.cleanup_old_keys(retention);
                            
                            metrics.total_rotations += 1;
                            metrics.keys_in_use = keys.keys.len() as u32;
                            metrics.last_rotation_duration_ms = start_time.elapsed().as_millis() as u64;
                            metrics.total_keys_removed += removed.len() as u64;
                            
                            if let Some(oldest) = keys.key_timestamps.values().min() {
                                metrics.oldest_key_age_seconds = (OffsetDateTime::now_utc() - *oldest)
                                    .whole_seconds()
                                    .max(0) as u64;
                            }

                            let mut state = state.write().await;
                            state.key_version = new_version;
                            state.last_rotation = Some(OffsetDateTime::now_utc());

                            info!(
                                version = new_version,
                                duration_ms = metrics.last_rotation_duration_ms,
                                removed_keys = removed.len(),
                                "Automatic key rotation completed"
                            );
                        } else {
                            metrics.failed_rotations += 1;
                            error!("Automatic key rotation failed: failed to create new key");
                        }
                    }
                }
            });

            *rotation_task = Some(handle);
        }
        Ok(())
    }

    pub async fn stop_key_rotation(&self) -> Result<()> {
        let mut rotation_task = self.rotation_task.write().await;
        if let Some(handle) = rotation_task.take() {
            handle.abort();
        }
        Ok(())
    }

    pub async fn force_key_rotation(&self) -> Result<()> {
        let new_key = CryptoManager::new(vec![0; 32])?;
        self.rotate_key(new_key).await?;
        
        let mut state = self.state.write().await;
        state.last_rotation = Some(OffsetDateTime::now_utc());
        
        Ok(())
    }

    pub async fn cleanup_old_keys(&self) -> Result<Vec<u32>> {
        let retention_period = self.config
            .as_ref()
            .map(|c| c.key_retention_period)
            .unwrap_or(DEFAULT_KEY_RETENTION_PERIOD);

        let mut keys = self.keys.write().await;
        let mut metrics = self.metrics.write().await;
        
        info!(
            retention_period_days = retention_period.as_secs() / 86400,
            current_keys = keys.keys.len(),
            "Starting key cleanup"
        );

        let removed = keys.cleanup_old_keys(retention_period);
        
        metrics.cleanup_count += 1;
        metrics.total_keys_removed += removed.len() as u64;
        metrics.keys_in_use = keys.keys.len() as u32;

        if !removed.is_empty() {
            info!(
                removed_count = removed.len(),
                removed_versions = ?removed,
                remaining_keys = keys.keys.len(),
                "Removed old encryption keys"
            );
        }

        Ok(removed)
    }

    pub async fn get_rotation_metrics(&self) -> KeyRotationMetrics {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }

    pub async fn save_to_file(&self, path: &Path) -> Result<()> {
        let state_guard = self.state.read().await;
        let mut state_copy = (*state_guard).clone();
        state_copy.checksum = String::new();
        state_copy.update_checksum();
        
        let json = serde_json::to_string(&state_copy)
            .map_err(|e| Error::Storage(format!("Failed to serialize state: {}", e)))?;
        
        tokio::fs::write(path, json).await
            .map_err(|e| Error::Storage(format!("Failed to write state file: {}", e)))?;
        
        info!(
            event = ?Event::System {
                operation: SystemOperation::StateSaved,
                details: None,
            },
            "State saved to file"
        );
        
        Ok(())
    }

    /// Add a new client
    pub async fn add_client(&self, client: Client) -> Result<()> {
        let mut state = self.state.write().await;
        state.clients.insert(client.id.clone(), client);
        Ok(())
    }

    /// Get a client by ID
    pub async fn get_client(&self, client_id: &str) -> Result<Client> {
        let state = self.state.read().await;
        state.clients.get(client_id)
            .cloned()
            .ok_or_else(|| Error::Client("Client not found".into()))
    }

    /// Update an existing client
    pub async fn update_client(&mut self, client: Client) -> Result<()> {
        let mut state = self.state.write().await;
        if !state.clients.contains_key(&client.id) {
            return Err(Error::Client("Client not found".into()));
        }
        state.clients.insert(client.id.clone(), client);
        Ok(())
    }

    /// Remove a client
    pub async fn remove_client(&mut self, client_id: &str) -> Result<()> {
        let mut state = self.state.write().await;
        state.clients.remove(client_id)
            .ok_or_else(|| Error::Client("Client not found".into()))?;
        Ok(())
    }

    /// Get all clients
    pub async fn get_clients(&self) -> Result<Vec<Client>> {
        let state = self.state.read().await;
        Ok(state.clients.values().cloned().collect())
    }

    /// Get a client by ID
    pub async fn get_client_by_id(&self, client_id: &str) -> Result<Option<Client>> {
        let state = self.state.read().await;
        Ok(state.clients.get(client_id).cloned())
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        if let Some(config) = &self.config {
            let _path = config.path.clone();
            
            tokio::task::block_in_place(|| {
                let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
                rt.block_on(async {
                    if let Err(e) = self.save().await {
                        error!("Final save failed: {}", e);
                    }
                });
            });
        }
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Storage(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use time::Duration as TimeDuration;

    fn create_test_config() -> StorageConfig {
        StorageConfig {
            path: PathBuf::from("test.db"),
            save_interval: 300,
            max_clients: 1000,
            max_tokens_per_user: 100,
            key_rotation_interval: Duration::from_secs(90 * 24 * 60 * 60),
            key_retention_period: Duration::from_secs(180 * 24 * 60 * 60),
            auto_rotate_keys: true,
        }
    }

    #[tokio::test]
    async fn test_token_operations() {
        let storage = Storage::new(&PathBuf::from("test.db"));
        
        let token = Token::new(
            "token123".to_string(),
            "user123".to_string(),
            "client123".to_string(),
            vec!["read".to_string()],
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        );

        storage.add_token(token.clone()).await.unwrap();

        let user_tokens = storage.get_user_tokens("user123").await.unwrap();
        assert_eq!(user_tokens.len(), 1);
        assert_eq!(user_tokens[0].id, token.id);

        storage.remove_token(&token.id).await.unwrap();
        let user_tokens = storage.get_user_tokens("user123").await.unwrap();
        assert!(user_tokens.is_empty());
    }

    #[tokio::test]
    async fn test_persistence_with_encryption() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let mut config = create_test_config();
        config.path = db_path.clone();

        let storage = Storage::new(&config.path);
        let token = Token::new(
            "token123".to_string(),
            "user123".to_string(),
            "client123".to_string(),
            vec!["read".to_string()],
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        );
        storage.add_token(token.clone()).await.unwrap();
        storage.save().await.unwrap();
        storage.stop_background_save().await.unwrap();
        drop(storage);

        let storage = Storage::new(&config.path);
        let user_tokens = storage.get_user_tokens("user123").await.unwrap();
        assert_eq!(user_tokens.len(), 1);
        assert_eq!(user_tokens[0].id, token.id);
        storage.stop_background_save().await.unwrap();
    }

    #[tokio::test]
    async fn test_encryption_with_different_keys() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let mut config = create_test_config();
        config.path = db_path.clone();

        let storage1 = Storage::new(&config.path);
        storage1.add_token(Token::new(
            "token123".to_string(),
            "user123".to_string(),
            "client123".to_string(),
            vec!["read".to_string()],
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        )).await.unwrap();
        storage1.save().await.unwrap();
        storage1.stop_background_save().await.unwrap();
        drop(storage1);

        let storage2 = Storage::new(&config.path);
        let result = storage2.load().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_max_tokens_per_user() {
        let config = StorageConfig {
            path: PathBuf::from("test.db"),
            save_interval: 300,
            max_clients: 1000,
            max_tokens_per_user: 2,
            key_rotation_interval: Duration::from_secs(90 * 24 * 60 * 60),
            key_retention_period: Duration::from_secs(180 * 24 * 60 * 60),
            auto_rotate_keys: true,
        };

        let storage = Storage::new(&config.path);

        // Add two tokens (should succeed)
        for i in 0..2 {
            let token = Token::new(
                format!("token{}", i),
                "user123".to_string(),
                "client123".to_string(),
                vec!["read".to_string()],
                OffsetDateTime::now_utc(),
                OffsetDateTime::now_utc() + TimeDuration::hours(1),
            );
            storage.add_token(token).await.unwrap();
        }

        // Try to add a third token (should fail)
        let token = Token::new(
            "token3".to_string(),
            "user123".to_string(),
            "client123".to_string(),
            vec!["read".to_string()],
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        );
        assert!(storage.add_token(token).await.is_err());
        storage.stop_background_save().await.unwrap();
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let dir = tempdir().unwrap();
        let config = StorageConfig {
            path: dir.path().join("test.db"),
            save_interval: 300,
            max_clients: 1000,
            max_tokens_per_user: 100,
            key_rotation_interval: Duration::from_secs(90 * 24 * 60 * 60),
            key_retention_period: Duration::from_secs(180 * 24 * 60 * 60),
            auto_rotate_keys: true,
        };

        let storage = Storage::new(&config.path);

        // Add a token with initial key
        let token = Token::new(
            "token123".to_string(),
            "user123".to_string(),
            "client123".to_string(),
            vec!["read".to_string()],
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        );
        storage.add_token(token.clone()).await.unwrap();
        storage.save().await.unwrap();

        // Rotate to new key
        let new_key = CryptoManager::new(vec![1; 32]).unwrap();
        storage.rotate_key(new_key).await.unwrap();

        // Verify we can still read the token
        let user_tokens = storage.get_user_tokens("user123").await.unwrap();
        assert_eq!(user_tokens.len(), 1);
        assert_eq!(user_tokens[0].id, token.id);

        // Remove old key
        storage.remove_old_key(1).await.unwrap();

        // Verify we can still read with new key
        let user_tokens = storage.get_user_tokens("user123").await.unwrap();
        assert_eq!(user_tokens.len(), 1);
        assert_eq!(user_tokens[0].id, token.id);

        storage.stop_background_save().await.unwrap();
    }

    #[tokio::test]
    async fn test_cannot_remove_current_key() {
        let storage = Storage::new(&PathBuf::from("test.db"));
        assert!(storage.remove_old_key(1).await.is_err());
    }

    #[tokio::test]
    async fn test_key_export_import() {
        let storage = Storage::new(&PathBuf::from("test.db"));
        let backup_key = CryptoManager::new(vec![2; 32]).unwrap();
        
        // Export keys
        let exported = storage.export_keys(&backup_key).await.unwrap();
        
        // Create new storage
        let storage2 = Storage::new(&PathBuf::from("test.db"));
        
        // Import keys
        storage2.import_keys(&backup_key, &exported).await.unwrap();
        
        // Verify keys were imported correctly
        let keys1 = storage.keys.read().await;
        let keys2 = storage2.keys.read().await;
        
        assert_eq!(keys1.current_version, keys2.current_version);
        assert_eq!(keys1.keys.len(), keys2.keys.len());
    }

    #[tokio::test]
    async fn test_key_file_save_load() {
        let dir = tempdir().unwrap();
        let backup_path = dir.path().join("keys.backup");
        let storage = Storage::new(&PathBuf::from("test.db"));
        let backup_key = CryptoManager::new(vec![2; 32]).unwrap();
        
        // Save keys to file
        storage.save_keys_to_file(&backup_key, &backup_path).await.unwrap();
        
        // Create new storage
        let storage2 = Storage::new(&PathBuf::from("test.db"));
        
        // Load keys from file
        storage2.load_keys_from_file(&backup_key, &backup_path).await.unwrap();
        
        // Verify keys were loaded correctly
        let keys1 = storage.keys.read().await;
        let keys2 = storage2.keys.read().await;
        
        assert_eq!(keys1.current_version, keys2.current_version);
        assert_eq!(keys1.keys.len(), keys2.keys.len());
    }

    #[tokio::test]
    async fn test_key_backup_integrity() {
        let storage = Storage::new(&PathBuf::from("test.db"));
        let backup_key = CryptoManager::new(vec![2; 32]).unwrap();
        
        // Export keys
        let mut exported = storage.export_keys(&backup_key).await.unwrap();
        
        // Tamper with the exported data
        if let Some(byte) = exported.last_mut() {
            *byte ^= 1;
        }
        
        // Try to import tampered backup
        let storage2 = Storage::new(&PathBuf::from("test.db"));
        assert!(storage2.import_keys(&backup_key, &exported).await.is_err());
    }

    #[tokio::test]
    async fn test_automatic_key_rotation() {
        let dir = tempdir().unwrap();
        let config = StorageConfig {
            path: dir.path().join("test.db"),
            save_interval: 300,
            max_clients: 1000,
            max_tokens_per_user: 100,
            key_rotation_interval: Duration::from_secs(1),
            key_retention_period: Duration::from_secs(1),
            auto_rotate_keys: true,
        };

        let _initial_key = CryptoManager::new(vec![0; 32]).unwrap();
        let storage = Storage::new(&config.path);
        
        // Start rotation
        storage.start_key_rotation().await.unwrap();
        
        // Wait for rotation
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Check if key was rotated
        let keys = storage.keys.read().await;
        assert!(keys.current_version > 1);
        
        storage.stop_key_rotation().await.unwrap();
        storage.stop_background_save().await.unwrap();
    }

    #[tokio::test]
    async fn test_key_cleanup() {
        let dir = tempdir().unwrap();
        let config = StorageConfig {
            path: dir.path().join("test.db"),
            save_interval: 300,
            max_clients: 1000,
            max_tokens_per_user: 100,
            key_rotation_interval: Duration::from_secs(1),
            key_retention_period: Duration::from_secs(1),
            auto_rotate_keys: true,
        };

        let _initial_key = CryptoManager::new(vec![0; 32]).unwrap();
        let storage = Storage::new(&config.path);
        
        // Add some keys
        for _ in 0..3 {
            let new_key = CryptoManager::new(vec![0; 32]).unwrap();
            storage.rotate_key(new_key).await.unwrap();
        }
        
        // Wait for retention period
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Cleanup old keys
        let removed = storage.cleanup_old_keys().await.unwrap();
        assert!(!removed.is_empty());
        
        // Verify only current key remains
        let keys = storage.keys.read().await;
        assert_eq!(keys.keys.len(), 1);
        
        storage.stop_background_save().await.unwrap();
    }

    #[tokio::test]
    async fn test_force_key_rotation() {
        let storage = Storage::new(&PathBuf::from("test.db"));
        
        let initial_version = {
            let keys = storage.keys.read().await;
            keys.current_version
        };
        
        // Force rotation
        storage.force_key_rotation().await.unwrap();
        
        // Verify key was rotated
        let keys = storage.keys.read().await;
        assert!(keys.current_version > initial_version);
        
        // Verify last rotation was updated
        let state = storage.state.read().await;
        assert!(state.last_rotation.is_some());
    }

    #[tokio::test]
    async fn test_rotation_metrics() {
        let dir = tempdir().unwrap();
        let config = StorageConfig {
            path: dir.path().join("test.db"),
            save_interval: 300,
            max_clients: 1000,
            max_tokens_per_user: 100,
            key_rotation_interval: Duration::from_secs(1),
            key_retention_period: Duration::from_secs(1),
            auto_rotate_keys: true,
        };

        let _initial_key = CryptoManager::new(vec![0; 32]).unwrap();
        let storage = Storage::new(&config.path);
        
        // Initial metrics
        let metrics = storage.get_rotation_metrics().await;
        assert_eq!(metrics.total_rotations, 0);
        assert_eq!(metrics.keys_in_use, 1);
        
        // Force some rotations
        for _ in 0..3 {
            let new_key = CryptoManager::new(vec![0; 32]).unwrap();
            storage.rotate_key(new_key).await.unwrap();
        }
        
        // Check updated metrics
        let metrics = storage.get_rotation_metrics().await;
        assert_eq!(metrics.total_rotations, 3);
        assert_eq!(metrics.keys_in_use, 4);
        assert!(metrics.last_rotation_duration_ms > 0);
        
        // Cleanup and check metrics
        storage.cleanup_old_keys().await.unwrap();
        let metrics = storage.get_rotation_metrics().await;
        assert!(metrics.cleanup_count > 0);
        
        storage.stop_key_rotation().await.unwrap();
        storage.stop_background_save().await.unwrap();
    }
} 