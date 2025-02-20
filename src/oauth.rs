use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::RwLock;
use std::sync::Arc;
use ring::rand::{SystemRandom, SecureRandom};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use tracing::info;
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::auth::AuthUser;
use crate::crypto::CryptoManager;
use crate::storage::Storage;
use crate::token::Token;
use crate::client::ClientManager;

const AUTH_CODE_EXPIRY: Duration = Duration::from_secs(600); // 10 minutes
const DEFAULT_TOKEN_EXPIRY: Duration = Duration::from_secs(3600); // 1 hour
const REFRESH_TOKEN_EXPIRY: Duration = Duration::from_secs(30 * 24 * 3600); // 30 days

/// Request for obtaining an access token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The grant type for the token request (e.g. "authorization_code", "refresh_token", "client_credentials")
    pub grant_type: String,
    /// The authorization code (only used with authorization_code grant type)
    pub code: String,
    /// The redirect URI that was used in the authorization request
    pub redirect_uri: String,
    /// The client identifier
    pub client_id: String,
    /// The client secret
    pub client_secret: String,
    /// The refresh token (only used with refresh_token grant type)
    pub refresh_token: Option<String>,
}

/// Response containing the access token and related information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token string
    pub access_token: String,
    /// The type of token (always "Bearer")
    pub token_type: String,
    /// Number of seconds until the token expires
    pub expires_in: u64,
    /// The refresh token that can be used to obtain new access tokens
    pub refresh_token: Option<String>,
    /// Space-separated list of scopes associated with the token
    pub scope: Option<String>,
}

/// Request for authorizing a client application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The client identifier
    pub client_id: String,
    /// The redirect URI where the authorization code will be sent
    pub redirect_uri: String,
    /// Space-separated list of requested scopes
    pub scope: Option<String>,
    /// Opaque value used to maintain state between the request and callback
    pub state: Option<String>,
    /// The response type (must be "code" for authorization code flow)
    pub response_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationCode {
    code: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    user: AuthUser,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshToken {
    token: String,
    client_id: String,
    user: AuthUser,
    scope: Option<String>,
    expires_at: OffsetDateTime,
}

/// Request for introspecting a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospectionRequest {
    /// The token string to introspect
    pub token: String,
    /// A hint about the type of token ("access_token" or "refresh_token")
    pub token_type_hint: Option<String>,
    /// The client identifier
    pub client_id: String,
    /// The client secret
    pub client_secret: String,
}

/// Response containing information about an introspected token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospectionResponse {
    /// Whether the token is currently active
    pub active: bool,
    /// Space-separated list of scopes associated with the token
    pub scope: Option<String>,
    /// The client identifier the token was issued to
    pub client_id: Option<String>,
    /// The username of the resource owner who authorized the token
    pub username: Option<String>,
    /// Timestamp when the token expires
    pub exp: Option<i64>,
    /// Timestamp when the token was issued
    pub iat: Option<i64>,
    /// The type of token (always "Bearer")
    pub token_type: Option<String>,
}

/// Request for revoking a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRevocationRequest {
    /// The token string to revoke
    pub token: String,
    /// A hint about the type of token ("access_token" or "refresh_token")
    pub token_type_hint: Option<String>,
    /// The client identifier
    pub client_id: String,
    /// The client secret
    pub client_secret: String,
}

/// Request for registering a new client application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationRequest {
    /// The name of the client application
    pub client_name: String,
    /// List of allowed redirect URIs
    pub redirect_uris: Vec<String>,
    /// List of allowed grant types
    pub grant_types: Vec<String>,
    /// Space-separated list of requested scopes
    pub scope: Option<String>,
    /// Identifier for the client software
    pub software_id: Option<String>,
    /// Version of the client software
    pub software_version: Option<String>,
}

/// Response containing the registered client credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    /// The client identifier
    pub client_id: String,
    /// The client secret
    pub client_secret: String,
    /// Timestamp when the client secret expires (0 means never)
    pub client_secret_expires_at: i64,
    /// Token for accessing the client registration
    pub registration_access_token: String,
    /// URI for accessing the client registration
    pub registration_client_uri: String,
    /// Timestamp when the client was registered
    pub client_id_issued_at: i64,
    /// List of allowed grant types
    pub grant_types: Vec<String>,
    /// List of allowed redirect URIs
    pub redirect_uris: Vec<String>,
    /// Space-separated list of allowed scopes
    pub scope: Option<String>,
}

/// Handles OAuth2 protocol flows and token management
pub struct OAuth2Flow {
    storage: Arc<Storage>,
    crypto: Arc<CryptoManager>,
    auth_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,
    client_secrets: Arc<RwLock<HashMap<String, String>>>,
    rng: SystemRandom,
}

impl OAuth2Flow {
    /// Creates a new OAuth2Flow instance with the given storage and crypto manager
    pub fn new(storage: Storage, crypto: CryptoManager) -> Self {
        Self {
            storage: Arc::new(storage),
            crypto: Arc::new(crypto),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            client_secrets: Arc::new(RwLock::new(HashMap::new())),
            rng: SystemRandom::new(),
        }
    }

    /// Verifies that the provided client secret matches the stored secret
    async fn verify_client_secret(&self, client_id: &str, provided_secret: &str) -> Result<()> {
        let secrets = self.client_secrets.read().await;
        match secrets.get(client_id) {
            Some(stored_secret) if stored_secret == provided_secret => Ok(()),
            _ => Err(Error::Auth("Invalid client_secret".into())),
        }
    }

    /// Stores a client secret for later verification
    async fn store_client_secret(&self, client_id: String, secret: String) {
        let mut secrets = self.client_secrets.write().await;
        secrets.insert(client_id, secret);
    }

    /// Validates an authorization request
    pub async fn validate_authorization_request(&self, request: &AuthorizationRequest) -> Result<()> {
        // Validate response type
        if request.response_type != "code" {
            return Err(Error::Auth("Invalid response type".into()));
        }

        // Validate client
        let client = self.storage.get_client_by_id(&request.client_id).await?
            .ok_or_else(|| Error::Auth("Invalid client_id".into()))?;

        // Validate redirect URI
        if client.redirect_url != request.redirect_uri {
            return Err(Error::Auth("Invalid redirect URI".into()));
        }

        // Validate scopes if present
        if let Some(scope) = &request.scope {
            let requested_scopes: Vec<_> = scope.split(' ').collect();
            for scope in requested_scopes {
                if !client.allowed_scopes.contains(&scope.to_string()) {
                    return Err(Error::Auth(format!("Invalid scope: {}", scope)));
                }
            }
        }

        Ok(())
    }

    /// Creates an authorization code for a user
    pub async fn create_authorization_code(
        &self,
        request: &AuthorizationRequest,
        user: AuthUser,
    ) -> Result<String> {
        // Generate secure random code
        let mut code_bytes = vec![0u8; 32];
        self.rng
            .fill(&mut code_bytes)
            .map_err(|_| Error::Auth("Failed to generate authorization code".into()))?;
        let code = URL_SAFE_NO_PAD.encode(&code_bytes);

        // Create authorization code entry
        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            user,
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(AUTH_CODE_EXPIRY.as_secs() as i64),
        };

        // Store the code
        let mut auth_codes = self.auth_codes.write().await;
        auth_codes.insert(code.clone(), auth_code);

        info!(
            client_id = %request.client_id,
            "Authorization code generated"
        );

        Ok(code)
    }

    async fn generate_refresh_token(&self, client_id: &str, user: &AuthUser, scope: Option<String>) -> Result<String> {
        let mut token_bytes = vec![0u8; 32];
        self.rng
            .fill(&mut token_bytes)
            .map_err(|_| Error::Auth("Failed to generate refresh token".into()))?;
        let token = URL_SAFE_NO_PAD.encode(&token_bytes);

        let refresh_token = RefreshToken {
            token: token.clone(),
            client_id: client_id.to_string(),
            user: user.clone(),
            scope,
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(REFRESH_TOKEN_EXPIRY.as_secs() as i64),
        };

        let mut refresh_tokens = self.refresh_tokens.write().await;
        refresh_tokens.insert(token.clone(), refresh_token);

        Ok(token)
    }

    /// Refreshes an access token using a refresh token
    pub async fn refresh_token(&self, request: &TokenRequest) -> Result<TokenResponse> {
        if request.grant_type != "refresh_token" {
            return Err(Error::Auth("Invalid grant type".into()));
        }

        let refresh_token = request.refresh_token
            .as_ref()
            .ok_or_else(|| Error::Auth("Refresh token is required".into()))?;

        let client = self.storage.get_client_by_id(&request.client_id).await?
            .ok_or_else(|| Error::Auth("Invalid client_id".into()))?;

        let client_id = client.id.clone();
        
        self.verify_client_secret(&client_id, &request.client_secret).await?;

        let mut refresh_tokens = self.refresh_tokens.write().await;
        let stored_token = refresh_tokens.get(refresh_token)
            .ok_or_else(|| Error::Auth("Invalid refresh token".into()))?;

        if stored_token.expires_at < OffsetDateTime::now_utc() {
            refresh_tokens.remove(refresh_token);
            return Err(Error::Auth("Refresh token expired".into()));
        }

        if stored_token.client_id != client_id {
            return Err(Error::Auth("Invalid client_id for refresh token".into()));
        }

        let token = stored_token.user.generate_token(
            &self.crypto,
            &client_id,
            DEFAULT_TOKEN_EXPIRY.as_secs() as i64,
        ).await?;

        self.storage.add_token(token.clone()).await?;

        info!(
            client_id = %client_id,
            user_id = %stored_token.user.id,
            "Access token refreshed"
        );

        Ok(TokenResponse {
            access_token: token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: DEFAULT_TOKEN_EXPIRY.as_secs(),
            refresh_token: Some(refresh_token.clone()),
            scope: stored_token.scope.clone(),
        })
    }

    /// Exchanges an authorization code for access and refresh tokens
    pub async fn exchange_authorization_code(&self, request: &TokenRequest) -> Result<TokenResponse> {
        let client = self.storage.get_client_by_id(&request.client_id).await?
            .ok_or_else(|| Error::Auth("Invalid client_id".into()))?;

        let client_id = client.id.clone();
        
        self.verify_client_secret(&client_id, &request.client_secret).await?;

        let mut auth_codes = self.auth_codes.write().await;
        let auth_code = auth_codes.remove(&request.code)
            .ok_or_else(|| Error::Auth("Invalid authorization code".into()))?;

        if auth_code.expires_at < OffsetDateTime::now_utc() {
            return Err(Error::Auth("Authorization code expired".into()));
        }

        if auth_code.client_id != client_id || auth_code.redirect_uri != request.redirect_uri {
            return Err(Error::Auth("Invalid client_id or redirect_uri".into()));
        }

        let refresh_token = self.generate_refresh_token(
            &client_id,
            &auth_code.user,
            auth_code.scope.clone(),
        ).await?;

        let token = auth_code.user.generate_token(
            &self.crypto,
            &client_id,
            DEFAULT_TOKEN_EXPIRY.as_secs() as i64,
        ).await?;

        self.storage.add_token(token.clone()).await?;

        info!(
            client_id = %client_id,
            user_id = %auth_code.user.id,
            "Access token and refresh token generated from authorization code"
        );

        Ok(TokenResponse {
            access_token: token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: DEFAULT_TOKEN_EXPIRY.as_secs(),
            refresh_token: Some(refresh_token),
            scope: auth_code.scope,
        })
    }

    /// Issues tokens using the client credentials grant type
    pub async fn client_credentials_grant(&self, request: &TokenRequest) -> Result<TokenResponse> {
        if request.grant_type != "client_credentials" {
            return Err(Error::Auth("Invalid grant type".into()));
        }

        let client = self.storage.get_client_by_id(&request.client_id).await?
            .ok_or_else(|| Error::Auth("Invalid client_id".into()))?;

        let client_id = client.id.clone();
        
        self.verify_client_secret(&client_id, &request.client_secret).await?;

        let scope_str = client.allowed_scopes.join(" ");
        let user = AuthUser {
            id: format!("service_{}", client_id),
            email: format!("service@{}", client_id),
            scopes: client.allowed_scopes,
            authenticated_at: OffsetDateTime::now_utc(),
        };

        let refresh_token = self.generate_refresh_token(
            &client_id,
            &user,
            Some(scope_str.clone()),
        ).await?;

        let token = user.generate_token(
            &self.crypto,
            &client_id,
            DEFAULT_TOKEN_EXPIRY.as_secs() as i64,
        ).await?;

        self.storage.add_token(token.clone()).await?;

        info!(
            client_id = %client_id,
            "Client credentials access token and refresh token generated"
        );

        Ok(TokenResponse {
            access_token: token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: DEFAULT_TOKEN_EXPIRY.as_secs(),
            refresh_token: Some(refresh_token),
            scope: Some(scope_str),
        })
    }

    /// Cleans up expired tokens from memory
    pub async fn cleanup_expired_tokens(&self) {
        let mut auth_codes = self.auth_codes.write().await;
        let mut refresh_tokens = self.refresh_tokens.write().await;
        let now = OffsetDateTime::now_utc();

        auth_codes.retain(|_, code| code.expires_at > now);
        refresh_tokens.retain(|_, token| token.expires_at > now);
    }

    /// Introspects a token to get information about it
    pub async fn introspect_token(&self, request: &TokenIntrospectionRequest) -> Result<TokenIntrospectionResponse> {
        let client = self.storage.get_client_by_id(&request.client_id).await?
            .ok_or_else(|| Error::Auth("Invalid client_id".into()))?;

        let client_id = client.id.clone();
        
        self.verify_client_secret(&client_id, &request.client_secret).await?;

        let token_str = &request.token;
        let decoded = URL_SAFE_NO_PAD.decode(token_str)
            .map_err(|_| Error::Auth("Invalid token format".into()))?;

        let decrypted = match self.crypto.decrypt(&decoded) {
            Ok(data) => data,
            Err(_) => {
                return Ok(TokenIntrospectionResponse {
                    active: false,
                    scope: None,
                    client_id: None,
                    username: None,
                    exp: None,
                    iat: None,
                    token_type: None,
                });
            }
        };

        let token_data: Token = match serde_json::from_slice(&decrypted) {
            Ok(data) => data,
            Err(_) => {
                return Ok(TokenIntrospectionResponse {
                    active: false,
                    scope: None,
                    client_id: None,
                    username: None,
                    exp: None,
                    iat: None,
                    token_type: None,
                });
            }
        };

        if token_data.expires_at < OffsetDateTime::now_utc() {
            return Ok(TokenIntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                exp: None,
                iat: None,
                token_type: None,
            });
        }

        Ok(TokenIntrospectionResponse {
            active: true,
            scope: Some(token_data.scopes.join(" ")),
            client_id: Some(token_data.client_id),
            username: Some(token_data.user_id),
            exp: Some(token_data.expires_at.unix_timestamp()),
            iat: Some(token_data.created_at.unix_timestamp()),
            token_type: Some("Bearer".to_string()),
        })
    }

    /// Revokes a token
    pub async fn revoke_token(&self, request: &TokenRevocationRequest) -> Result<()> {
        let client = self.storage.get_client_by_id(&request.client_id).await?
            .ok_or_else(|| Error::Auth("Invalid client_id".into()))?;

        let client_id = client.id.clone();
        
        self.verify_client_secret(&client_id, &request.client_secret).await?;

        let token_type_hint = request.token_type_hint.as_deref().unwrap_or("access_token");

        match token_type_hint {
            "refresh_token" => {
                let mut refresh_tokens = self.refresh_tokens.write().await;
                refresh_tokens.remove(&request.token);
            }
            "access_token" | _ => {
                self.storage.remove_token(&request.token).await?;
            }
        }

        info!(
            client_id = %client_id,
            token_type = %token_type_hint,
            "Token revoked"
        );

        Ok(())
    }

    /// Registers a new client application
    pub async fn register_client(&self, request: &ClientRegistrationRequest) -> Result<ClientRegistrationResponse> {
        for grant_type in &request.grant_types {
            match grant_type.as_str() {
                "authorization_code" | "client_credentials" | "refresh_token" => {}
                _ => return Err(Error::Auth(format!("Unsupported grant type: {}", grant_type))),
            }
        }

        if request.redirect_uris.is_empty() {
            return Err(Error::Auth("At least one redirect URI is required".into()));
        }

        let client_manager = ClientManager::new((*self.storage).clone());
        let client = client_manager.create()
            .name(&request.client_name)
            .redirect_url(&request.redirect_uris[0])
            .allowed_scopes(&request.scope
                .as_deref()
                .unwrap_or("")
                .split(' ')
                .collect::<Vec<_>>())
            .save()
            .await?;

        let client_id = client.id.clone();
        let client_secret = nanoid::nanoid!(32);
        
        self.store_client_secret(client_id.clone(), client_secret.clone()).await;

        let now = OffsetDateTime::now_utc();
        
        info!(
            client_id = %client_id,
            name = %request.client_name,
            "New client registered"
        );

        Ok(ClientRegistrationResponse {
            client_id,
            client_secret,
            client_secret_expires_at: 0,
            registration_access_token: String::new(),
            registration_client_uri: String::new(),
            client_id_issued_at: now.unix_timestamp(),
            grant_types: request.grant_types.clone(),
            redirect_uris: request.redirect_uris.clone(),
            scope: request.scope.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;

    async fn create_test_flow() -> (OAuth2Flow, Client, AuthUser) {
        let storage = Storage::new_in_memory();
        let crypto = CryptoManager::new(vec![0; 32]).unwrap();
        let flow = OAuth2Flow::new(storage, crypto);

        let client = Client::new(
            "test_client".to_string(),
            "Test Client".to_string(),
            "https://example.com/callback".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        flow.store_client_secret(client.id.clone(), "test_secret".to_string()).await;

        let user = AuthUser {
            id: "test_user".to_string(),
            email: "test@example.com".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            authenticated_at: OffsetDateTime::now_utc(),
        };

        (flow, client, user)
    }

    #[tokio::test]
    async fn test_authorization_flow() {
        let (flow, client, user) = create_test_flow().await;

        // Test authorization request validation
        let auth_request = AuthorizationRequest {
            client_id: client.id.clone(),
            redirect_uri: client.redirect_url.clone(),
            scope: Some("read write".to_string()),
            state: Some("xyz".to_string()),
            response_type: "code".to_string(),
        };

        assert!(flow.validate_authorization_request(&auth_request).await.is_ok());

        // Test authorization code creation
        let code = flow.create_authorization_code(&auth_request, user.clone()).await.unwrap();
        assert!(!code.is_empty());

        // Test token exchange
        let token_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: code.clone(),
            redirect_uri: client.redirect_url.clone(),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
            refresh_token: None,
        };

        let token_response = flow.exchange_authorization_code(&token_request).await.unwrap();
        assert_eq!(token_response.token_type, "Bearer");
        assert_eq!(token_response.expires_in, DEFAULT_TOKEN_EXPIRY.as_secs());
        assert_eq!(token_response.scope, Some("read write".to_string()));

        // Test code is consumed
        assert!(flow.exchange_authorization_code(&token_request).await.is_err());
    }

    #[tokio::test]
    async fn test_refresh_token_flow() {
        let (flow, client, user) = create_test_flow().await;

        // First get an authorization code
        let auth_request = AuthorizationRequest {
            client_id: client.id.clone(),
            redirect_uri: client.redirect_url.clone(),
            scope: Some("read write".to_string()),
            state: Some("xyz".to_string()),
            response_type: "code".to_string(),
        };

        let code = flow.create_authorization_code(&auth_request, user.clone()).await.unwrap();

        // Exchange it for tokens
        let token_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: code.clone(),
            redirect_uri: client.redirect_url.clone(),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
            refresh_token: None,
        };

        let token_response = flow.exchange_authorization_code(&token_request).await.unwrap();
        assert!(token_response.refresh_token.is_some());

        // Use refresh token to get new access token
        let refresh_request = TokenRequest {
            grant_type: "refresh_token".to_string(),
            code: String::new(),
            redirect_uri: String::new(),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
            refresh_token: token_response.refresh_token.clone(),
        };

        let refreshed_response = flow.refresh_token(&refresh_request).await.unwrap();
        assert_eq!(refreshed_response.token_type, "Bearer");
        assert_eq!(refreshed_response.expires_in, DEFAULT_TOKEN_EXPIRY.as_secs());
        assert_eq!(refreshed_response.scope, Some("read write".to_string()));
        assert_eq!(refreshed_response.refresh_token, token_response.refresh_token);

        // Test invalid refresh token
        let mut invalid_request = refresh_request.clone();
        invalid_request.refresh_token = Some("invalid_token".to_string());
        assert!(flow.refresh_token(&invalid_request).await.is_err());
    }

    #[tokio::test]
    async fn test_expired_token_cleanup() {
        let (flow, client, user) = create_test_flow().await;

        // Create an authorization code and get tokens
        let auth_request = AuthorizationRequest {
            client_id: client.id.clone(),
            redirect_uri: client.redirect_url.clone(),
            scope: None,
            state: None,
            response_type: "code".to_string(),
        };

        let code = flow.create_authorization_code(&auth_request, user.clone()).await.unwrap();
        
        // Manually expire the code
        {
            let mut auth_codes = flow.auth_codes.write().await;
            if let Some(auth_code) = auth_codes.get_mut(&code) {
                auth_code.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
            }
        }

        // Create a refresh token and expire it
        let refresh_token = flow.generate_refresh_token(&client.id, &user, None).await.unwrap();
        {
            let mut refresh_tokens = flow.refresh_tokens.write().await;
            if let Some(token) = refresh_tokens.get_mut(&refresh_token) {
                token.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
            }
        }

        // Run cleanup
        flow.cleanup_expired_tokens().await;

        // Verify both were cleaned up
        let auth_codes = flow.auth_codes.read().await;
        let refresh_tokens = flow.refresh_tokens.read().await;
        assert!(!auth_codes.contains_key(&code));
        assert!(!refresh_tokens.contains_key(&refresh_token));
    }

    #[tokio::test]
    async fn test_token_introspection() {
        let (flow, client, user) = create_test_flow().await;

        // First get an access token
        let auth_request = AuthorizationRequest {
            client_id: client.id.clone(),
            redirect_uri: client.redirect_url.clone(),
            scope: Some("read write".to_string()),
            state: Some("xyz".to_string()),
            response_type: "code".to_string(),
        };

        let code = flow.create_authorization_code(&auth_request, user.clone()).await.unwrap();
        let token_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code,
            redirect_uri: client.redirect_url.clone(),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
            refresh_token: None,
        };

        let token_response = flow.exchange_authorization_code(&token_request).await.unwrap();

        // Introspect the token
        let introspection_request = TokenIntrospectionRequest {
            token: token_response.access_token,
            token_type_hint: Some("access_token".to_string()),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
        };

        let introspection_response = flow.introspect_token(&introspection_request).await.unwrap();
        assert!(introspection_response.active);
        assert_eq!(introspection_response.scope, Some("read write".to_string()));
        assert_eq!(introspection_response.client_id, Some(client.id.clone()));
    }

    #[tokio::test]
    async fn test_token_revocation() {
        let (flow, client, user) = create_test_flow().await;

        // First get tokens
        let auth_request = AuthorizationRequest {
            client_id: client.id.clone(),
            redirect_uri: client.redirect_url.clone(),
            scope: Some("read write".to_string()),
            state: Some("xyz".to_string()),
            response_type: "code".to_string(),
        };

        let code = flow.create_authorization_code(&auth_request, user.clone()).await.unwrap();
        let token_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code,
            redirect_uri: client.redirect_url.clone(),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
            refresh_token: None,
        };

        let token_response = flow.exchange_authorization_code(&token_request).await.unwrap();

        // Revoke the access token
        let revocation_request = TokenRevocationRequest {
            token: token_response.access_token.clone(),
            token_type_hint: Some("access_token".to_string()),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
        };

        assert!(flow.revoke_token(&revocation_request).await.is_ok());

        // Verify token is no longer active
        let introspection_request = TokenIntrospectionRequest {
            token: token_response.access_token,
            token_type_hint: Some("access_token".to_string()),
            client_id: client.id.clone(),
            client_secret: "test_secret".to_string(),
        };

        let introspection_response = flow.introspect_token(&introspection_request).await.unwrap();
        assert!(!introspection_response.active);
    }

    #[tokio::test]
    async fn test_client_registration() {
        let (flow, _, _) = create_test_flow().await;

        let registration_request = ClientRegistrationRequest {
            client_name: "Test App".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            scope: Some("read write".to_string()),
            software_id: Some("test-suite".to_string()),
            software_version: Some("1.0".to_string()),
        };

        let response = flow.register_client(&registration_request).await.unwrap();
        assert!(!response.client_id.is_empty());
        assert!(!response.client_secret.is_empty());
        assert_eq!(response.grant_types, registration_request.grant_types);
        assert_eq!(response.redirect_uris, registration_request.redirect_uris);
        assert_eq!(response.scope, registration_request.scope);

        // Verify we can use the new client credentials
        let auth_request = AuthorizationRequest {
            client_id: response.client_id.clone(),
            redirect_uri: response.redirect_uris[0].clone(),
            scope: response.scope.clone(),
            state: Some("xyz".to_string()),
            response_type: "code".to_string(),
        };

        assert!(flow.validate_authorization_request(&auth_request).await.is_ok());
    }
} 