# MicroAuth

MicroAuth is an ultra-low-level in-memory auth server. It makes OAuth2 authentication in a breeze by providing a ORM-like API. Built on top of `ring` crate with BoringSSL bindings.

## Design Philosophy

For a lot of prod usecases it's not necessary to have a separate auth server because a single high-performance webserver can handle all requests and do all auth in-memory. Crypto implementations such as those in `ring` are extremely fast but if hidden behind a slow sso portal such as auth0, google etc. might be perceived as sluggish due to >1sec loadtimes.

db analogy: in-memory sqlite over hosted postgres.

## Quick Start

```rust
use microauth::prelude::*;

#[tokio::main]
async fn main() {
    // Initialize the auth server
    let auth = MicroAuth::new()
        .with_app_name("My Bloated AI App")
        .persist_to("./auth.db")
        .init()
        .await?;

    // Create a new client (like creating a new user in an ORM)
    let client = auth.clients()
        .create()
        .name("My Bloated mobile app")
        .redirect_url("myapp://auth")
        .save()
        .await?;

    println!("Client ID: {}", client.id);
    println!("Client Secret: {}", client.secret);
}
```

## Common Use Cases

### User Authentication

```rust
// In your login route handler
async fn login(auth: &MicroAuth) -> Result<impl Response> {
    let auth_url = auth.flows()
        .authorization_code()
        .for_client("mobile_app")
        .with_scopes(&["profile", "email"])
        .generate_url()?;

    Ok(Redirect::to(auth_url))
}

// In your callback route handler
async fn callback(auth: &MicroAuth, code: String) -> Result<impl Response> {
    let user = auth.flows()
        .verify_code(code)
        .await?;

    println!("Authenticated user: {}", user.email);
    
    // Get a token for future requests
    let token = user.generate_token().await?;
    
    Ok(json!({ "token": token.to_string() }))
}
```

### Protecting Routes

```rust
#[derive(AuthGuard)]
struct MyApi;

#[guard(scope = "admin")]
async fn admin_only(user: AuthUser) -> impl Response {
    format!("Hello admin: {}", user.email)
}

#[guard(scope = "basic")]
async fn basic_access(user: AuthUser) -> impl Response {
    format!("Hello user: {}", user.email)
}
```

### Token Management

```rust
// Verify a token
let user = auth.tokens()
    .verify(token_string)
    .await?;

// Revoke a token
auth.tokens()
    .revoke(token_string)
    .await?;

// List active tokens for a user
let tokens = auth.tokens()
    .for_user(user_id)
    .list()
    .await?;
```

### Client Management

```rust
// List all clients
let clients = auth.clients()
    .list()
    .await?;

// Update a client
auth.clients()
    .update(client_id)
    .name("Updated Name")
    .redirect_url("newapp://auth")
    .save()
    .await?;

// Delete a client
auth.clients()
    .delete(client_id)
    .await?;
```

## Configuration

While MicroAuth works out of the box, you can customize it to your needs:

```rust
let auth = MicroAuth::new()
    // Basic settings
    .app_name("My App")
    .persist_to("./auth.db")
    
    // Optional customization
    .token_expiry(Duration::from_hours(24))
    .max_tokens_per_user(100)
    .auto_cleanup(true)
    
    // Advanced settings (with sensible defaults)
    .persistence_interval(Duration::from_secs(300))
    .max_clients(1000)
    .rate_limit(100, Duration::from_secs(60))
    
    .init()
    .await?;
```

### Cryptographic Configuration

```rust
use microauth::crypto::{CryptoConfig, KeySource};

let auth = MicroAuth::new()
    // Key management
    .with_master_key(KeySource::File("master.key"))
    .with_key_rotation_interval(Duration::from_days(90))
    .with_key_backup_count(2)
    
    // State encryption
    .with_crypto_config(CryptoConfig {
        auto_rotate_keys: true,
        keep_backup_keys: true,
        cleanup_old_keys: true,
    })
    
    // Token settings
    .with_token_encryption(true)
    .with_token_signing_algorithm("ES256")
    
    .init()
    .await?;

// Manual key rotation
auth.storage()
    .rotate_key(new_key)
    .await?;

// Key backup and export
let key_backup = auth.storage()
    .export_keys()
    .with_encryption(backup_key)
    .save_to("keys.backup")
    .await?;
```

## Framework Integration

MicroAuth works with any async Rust web framework:

```rust
// Axum example
async fn create_auth_routes() -> Router {
    let auth = MicroAuth::new().init().await?;
    
    Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .with_state(auth)
}

// Actix example
App::new()
    .app_data(web::Data::new(auth))
    .service(web::resource("/auth").to(auth_routes))
```

## Security

Some things MicroAuth handles for you (prob forgot something important):

### Crypto

#### State Encryption

- ChaCha20-Poly1305 AEAD encryption for all persistent data
- Authenticated encryption prevents memory tampering
- Atomic file operations with backup support
- Base64 URL-safe encoding for storage

#### Key Management

- Secure key generation and validation
- Support for multiple active encryption keys
- Key versioning and rotation
- Safe removal of old keys
- Automatic key derivation via zero-trust principle

#### Key Rotation

```rust
// Rotate to a new encryption key
auth.storage()
    .rotate_key(new_key)
    .await?;

// Remove old key after rotation
auth.storage()
    .remove_old_key(old_version)
    .await?;
```

#### Backup and Recovery

- periodic, atomic, encrypted backup creation during saves
- Fallback to backup on corruption
- Multi-key support for recovery (not exposed right now via api)

### Token Security

- Secure token generation and validation
- Automatic token expiration
- Token revocation support
- Scope-based access control
- Protection against replay attacks

### Access Control

- Fine-grained scope management
- Client authentication
- Rate limiting
- Token blacklisting
- Concurrent access protection

### Other

- No unsafe code
- Memory zeroing for sensitive data
- Constant-time comparisons
- Secure random number generation
- Automatic cleanup of expired data

## License

MIT