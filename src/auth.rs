//! Core authentication types and functionality

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use crate::crypto::CryptoManager;
use crate::error::{Error, Result};
use crate::token::Token;

/// Represents an authenticated user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    /// Unique identifier for the user
    pub id: String,
    
    /// User's email address
    pub email: String,
    
    /// List of granted scopes
    pub scopes: Vec<String>,
    
    /// When the user was authenticated
    pub authenticated_at: OffsetDateTime,
}

/// Claims contained within a JWT token
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
    /// Granted scopes
    pub scopes: Vec<String>,
    /// Client ID
    pub client_id: String,
}

impl AuthUser {
    /// Generate a new token for this user
    pub async fn generate_token(&self, crypto: &CryptoManager, client_id: &str, expires_in: i64) -> Result<Token> {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(expires_in);

        let claims = TokenClaims {
            sub: self.id.clone(),
            exp: expires_at.unix_timestamp(),
            iat: now.unix_timestamp(),
            scopes: self.scopes.clone(),
            client_id: client_id.to_string(),
        };

        let claims_json = serde_json::to_vec(&claims)
            .map_err(|e| Error::Token(format!("Failed to serialize claims: {}", e)))?;

        let encrypted_claims = crypto.encrypt(&claims_json)
            .map_err(|e| Error::Token(format!("Failed to encrypt claims: {}", e)))?;

        let token_string = URL_SAFE_NO_PAD.encode(&encrypted_claims);

        Ok(Token::new(
            token_string,
            self.id.clone(),
            client_id.to_string(),
            self.scopes.clone(),
            now,
            expires_at,
        ))
    }
}

/// Builder for configuring authentication flows
#[derive(Debug)]
pub struct AuthFlow {
    client_id: Option<String>,
    scopes: Vec<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    crypto: CryptoManager,
}

impl AuthFlow {
    /// Create a new authorization code flow
    pub fn authorization_code(crypto: CryptoManager) -> Self {
        Self {
            client_id: None,
            scopes: Vec::new(),
            redirect_uri: None,
            state: None,
            crypto,
        }
    }

    /// Specify the client for this flow
    pub fn for_client(mut self, client_id: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self
    }

    /// Add scopes to the authentication request
    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(ToString::to_string).collect();
        self
    }

    /// Add a redirect URI to the authentication request
    pub fn with_redirect_uri(mut self, uri: &str) -> Self {
        self.redirect_uri = Some(uri.to_string());
        self
    }

    /// Add a state to the authentication request
    pub fn with_state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    /// Generate the authorization URL
    pub fn generate_url(self) -> Result<String> {
        let client_id = self.client_id.ok_or_else(|| 
            Error::Auth("Client ID is required".into()))?;
        let redirect_uri = self.redirect_uri.ok_or_else(|| 
            Error::Auth("Redirect URI is required".into()))?;

        let mut params = Vec::new();
        params.push(("response_type".to_string(), "code".to_string()));
        params.push(("client_id".to_string(), client_id));
        params.push(("redirect_uri".to_string(), redirect_uri));

        if !self.scopes.is_empty() {
            params.push(("scope".to_string(), self.scopes.join(" ")));
        }

        if let Some(state) = self.state {
            params.push(("state".to_string(), state));
        }

        let query = params.iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(format!("/oauth/authorize?{}", query))
    }

    /// Verify an authorization code
    pub async fn verify_code(&self, code: String) -> Result<AuthUser> {
        let decoded = URL_SAFE_NO_PAD.decode(code)
            .map_err(|_| Error::Auth("Invalid authorization code".into()))?;

        let decrypted = self.crypto.decrypt(&decoded)
            .map_err(|_| Error::Auth("Failed to decrypt authorization code".into()))?;

        let auth_data: AuthUser = serde_json::from_slice(&decrypted)
            .map_err(|_| Error::Auth("Invalid authorization code data".into()))?;

        if auth_data.authenticated_at + time::Duration::minutes(10) < OffsetDateTime::now_utc() {
            return Err(Error::Auth("Authorization code expired".into()));
        }

        Ok(auth_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_crypto() -> CryptoManager {
        let key = vec![0; 32];
        CryptoManager::new(key).unwrap()
    }

    #[test]
    fn test_auth_flow_url_generation() {
        let crypto = create_test_crypto();
        let url = AuthFlow::authorization_code(crypto)
            .for_client("client123")
            .with_scopes(&["read", "write"])
            .with_redirect_uri("https://example.com/callback")
            .with_state("xyz789")
            .generate_url()
            .unwrap();

        assert!(url.starts_with("/oauth/authorize"));
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("scope=read%20write"));
        assert!(url.contains("state=xyz789"));
    }

    #[tokio::test]
    async fn test_token_generation() {
        let crypto = create_test_crypto();
        let user = AuthUser {
            id: "user123".to_string(),
            email: "user@example.com".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            authenticated_at: OffsetDateTime::now_utc(),
        };

        let token = user.generate_token(&crypto, "client123", 3600).await.unwrap();

        assert_eq!(token.user_id, "user123");
        assert_eq!(token.client_id, "client123");
        assert_eq!(token.scopes, vec!["read", "write"]);
        assert!(token.expires_at > token.created_at);
    }

    #[tokio::test]
    async fn test_code_verification() {
        let crypto = create_test_crypto();
        let auth_flow = AuthFlow::authorization_code(crypto.clone());
        let user = AuthUser {
            id: "user123".to_string(),
            email: "user@example.com".to_string(),
            scopes: vec!["read".to_string()],
            authenticated_at: OffsetDateTime::now_utc(),
        };

        let user_data = serde_json::to_vec(&user).unwrap();
        let encrypted = crypto.encrypt(&user_data).unwrap();
        let code = URL_SAFE_NO_PAD.encode(encrypted);

        let verified = auth_flow.verify_code(code).await.unwrap();
        assert_eq!(verified.id, user.id);
        assert_eq!(verified.email, user.email);
        assert_eq!(verified.scopes, user.scopes);
    }
} 