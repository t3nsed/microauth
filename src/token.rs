//! Token management and validation

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::auth::TokenClaims;
use crate::crypto::CryptoManager;
use crate::error::{Error, Result};
use crate::storage::Storage;

/// Represents an authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Unique identifier for the token
    pub id: String,
    
    /// The actual token string
    token: String,
    
    /// When the token was created
    pub created_at: OffsetDateTime,
    
    /// When the token expires
    pub expires_at: OffsetDateTime,
    
    /// List of granted scopes
    pub scopes: Vec<String>,
    
    /// ID of the user this token belongs to
    pub user_id: String,
    
    /// ID of the client this token was issued to
    pub client_id: String,
}

impl Token {
    /// Create a new token
    pub fn new(
        token: String,
        user_id: String,
        client_id: String,
        scopes: Vec<String>,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            id: nanoid::nanoid!(),
            token,
            created_at,
            expires_at,
            scopes,
            user_id,
            client_id,
        }
    }

    /// Convert the token to a string for use in requests
    pub fn to_string(&self) -> String {
        self.token.clone()
    }

    fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }
}

/// Builder for token operations
#[derive(Debug)]
pub struct TokenManager {
    crypto: Arc<CryptoManager>,
    storage: Arc<RwLock<Storage>>,
    revoked_tokens: Arc<RwLock<Vec<String>>>,
}

impl TokenManager {
    /// Creates a new TokenManager with the given crypto manager and storage
    pub fn new(crypto: CryptoManager, storage: Storage) -> Self {
        Self {
            crypto: Arc::new(crypto),
            storage: Arc::new(RwLock::new(storage)),
            revoked_tokens: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Verify a token string
    pub async fn verify(&self, token_string: String) -> Result<Token> {
        let decoded = URL_SAFE_NO_PAD.decode(&token_string)
            .map_err(|_| Error::Token("Invalid token format".into()))?;

        let decrypted = self.crypto.decrypt(&decoded)
            .map_err(|_| Error::Token("Failed to decrypt token".into()))?;

        let claims: TokenClaims = serde_json::from_slice(&decrypted)
            .map_err(|_| Error::Token("Invalid token data".into()))?;

        let now = OffsetDateTime::now_utc().unix_timestamp();
        if claims.exp <= now {
            return Err(Error::Token("Token has expired".into()));
        }

        let revoked_tokens = self.revoked_tokens.read().await;
        if revoked_tokens.contains(&token_string) {
            return Err(Error::Token("Token has been revoked".into()));
        }

        let token = Token::new(
            token_string,
            claims.sub,
            claims.client_id,
            claims.scopes,
            OffsetDateTime::from_unix_timestamp(claims.iat)
                .map_err(|_| Error::Token("Invalid token timestamp".into()))?,
            OffsetDateTime::from_unix_timestamp(claims.exp)
                .map_err(|_| Error::Token("Invalid token timestamp".into()))?,
        );

        Ok(token)
    }

    /// Revoke a token
    pub async fn revoke(&self, token_string: String) -> Result<()> {
        let token = self.verify(token_string.clone()).await?;

        if token.is_expired() {
            return Err(Error::Token("Cannot revoke expired token".into()));
        }

        let mut revoked_tokens = self.revoked_tokens.write().await;
        revoked_tokens.push(token_string);

        let storage = self.storage.write().await;
        storage.save().await?;

        Ok(())
    }

    /// List tokens for a specific user
    pub fn for_user(&self, user_id: String) -> TokenListBuilder {
        TokenListBuilder {
            user_id,
            storage: Arc::clone(&self.storage),
            revoked_tokens: Arc::clone(&self.revoked_tokens),
        }
    }

    /// Removes expired tokens from the revoked tokens list and returns the number of tokens removed
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let mut revoked_tokens = self.revoked_tokens.write().await;
        let initial_len = revoked_tokens.len();

        let storage = self.storage.write().await;

        let mut valid_tokens = Vec::new();
        for token_string in revoked_tokens.iter() {
            if let Ok(token) = self.verify(token_string.clone()).await {
                if !token.is_expired() {
                    valid_tokens.push(token_string.clone());
                }
            }
        }

        revoked_tokens.clear();
        revoked_tokens.extend(valid_tokens);

        if revoked_tokens.len() != initial_len {
            storage.save().await?;
        }

        Ok(initial_len - revoked_tokens.len())
    }
}

/// Builder for listing tokens
#[derive(Debug)]
pub struct TokenListBuilder {
    user_id: String,
    storage: Arc<RwLock<Storage>>,
    revoked_tokens: Arc<RwLock<Vec<String>>>,
}

impl TokenListBuilder {
    /// Execute the token list operation
    pub async fn list(self) -> Result<Vec<Token>> {
        let storage = self.storage.read().await;
        let revoked_tokens = self.revoked_tokens.read().await;

        let mut tokens = storage.get_user_tokens(&self.user_id).await?;
        tokens.retain(|token| {
            !token.is_expired() && !revoked_tokens.contains(&token.to_string())
        });

        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthUser;
    use std::time::Duration;

    async fn create_test_token() -> (TokenManager, Token) {
        let key = vec![0; 32];
        let crypto = CryptoManager::new(key).unwrap();
        let storage = Storage::new_in_memory();
        let manager = TokenManager::new(crypto.clone(), storage);

        let user = AuthUser {
            id: "user123".to_string(),
            email: "user@example.com".to_string(),
            scopes: vec!["read".to_string()],
            authenticated_at: OffsetDateTime::now_utc(),
        };

        let token = user.generate_token(&crypto, "client123", 3600).await.unwrap();
        (manager, token)
    }

    #[tokio::test]
    async fn test_token_verification() {
        let (manager, token) = create_test_token().await;
        let token_str = token.to_string();
        
        let verified = manager.verify(token_str).await.unwrap();
        assert_eq!(verified.user_id, "user123");
        assert_eq!(verified.client_id, "client123");
    }

    #[tokio::test]
    async fn test_token_revocation() {
        let (manager, token) = create_test_token().await;
        let token_str = token.to_string();

        manager.revoke(token_str.clone()).await.unwrap();
        assert!(manager.verify(token_str).await.is_err());
    }

    #[tokio::test]
    async fn test_expired_token() {
        let (manager, mut token) = create_test_token().await;
        token.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
        
        assert!(token.is_expired());
        assert!(manager.verify(token.to_string()).await.is_err());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let (manager, token) = create_test_token().await;
        let token_str = token.to_string();

        manager.revoke(token_str).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        let cleaned = manager.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 0); // Token shouldn't be cleaned up yet

        // Force token expiration
        let mut token = token;
        token.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
        
        let cleaned = manager.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 1); // Token should be cleaned up now
    }
} 