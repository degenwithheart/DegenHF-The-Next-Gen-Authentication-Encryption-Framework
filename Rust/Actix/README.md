# DegenHF ECC Auth - Actix Web

ECC-based authentication package for Actix Web with enhanced security and performance.

## Features

- **ECC secp256k1 Cryptography**: Blockchain-grade elliptic curve operations
- **Hybrid Password Hashing**: Argon2 + BLAKE3 for GPU-hard security
- **JWT Token Management**: ES256 signed tokens with ECC keys
- **LRU Caching**: High-performance token verification caching
- **Actix Middleware**: Seamless integration with Actix Web middleware system
- **Async/Await**: Full async support with Tokio
- **Memory Safety**: Rust's ownership system prevents common vulnerabilities
- **Constant-Time Operations**: Protection against timing attacks

## Installation

Since this package is currently only available from the GitHub repository, add it to your `Cargo.toml`:

```toml
[dependencies]
degenhf-ecc-auth-actix = { git = "https://github.com/degenwithheart/DegenHF-The-Next-Gen-Authentication-Encryption-Framework", path = "Rust/Actix" }
```

## Quick Start

```rust
use actix_web::{web, App, HttpServer, Result as ActixResult};
use actix_web_httpauth::middleware::HttpAuthentication;
use actix_web_httpauth::extractors::bearer::bearer_validator;
use degenhf_ecc_auth_actix::{EccAuthHandler, EccAuthOptions};
use std::sync::Arc;

async fn protected_route(user: web::ReqData<UserClaims>) -> ActixResult<String> {
    Ok(format!("Hello, {}!", user.username))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let options = EccAuthOptions {
        hash_iterations: 100000,
        token_expiry: Duration::hours(24),
        cache_size: 10000,
        cache_ttl: Duration::minutes(5),
    };

    let auth_handler = Arc::new(
        EccAuthHandler::new(Some(options))
            .expect("Failed to initialize auth handler")
    );

    HttpServer::new(move || {
        let auth = HttpAuthentication::bearer(bearer_validator);

        App::new()
            .app_data(web::Data::new(auth_handler.clone()))
            .service(
                web::scope("/api")
                    .wrap(auth)
                    .route("/protected", web::get().to(protected_route))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration

```rust
use degenhf_ecc_auth_actix::EccAuthOptions;
use chrono::Duration;

let options = EccAuthOptions {
    hash_iterations: 100000,        // Argon2 iterations
    token_expiry: Duration::hours(24), // JWT expiry
    cache_size: 10000,              // LRU cache size
    cache_ttl: Duration::minutes(5), // Cache TTL
};

let auth_handler = EccAuthHandler::new(Some(options))?;
```

## API Reference

### Core Types

#### `EccAuthHandler`
Main authentication handler with ECC operations.

#### `EccAuthOptions`
Configuration options for authentication.

#### `UserSession`
User session data structure.

#### `UserClaims`
User claims from verified token.

### Methods

#### `new(options)`
Creates a new ECC authentication handler.

#### `register(username, password)`
Registers a new user with ECC-secured password hashing.

#### `authenticate(username, password)`
Authenticates user and returns JWT token.

#### `verify_token(token)`
Verifies JWT token and returns user data.

#### `create_session(user_id)`
Creates a secure session.

#### `get_session(session_id)`
Retrieves session data.

## API Endpoints

### Public Endpoints

#### POST /api/auth/register
Register a new user.

**Request:**
```json
{
  "username": "johndoe",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "user_id": "user_1234567890",
  "message": "User registered successfully"
}
```

#### POST /api/auth/login
Authenticate user and get token.

**Request:**
```json
{
  "username": "johndoe",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "message": "Login successful"
}
```

### Protected Endpoints

#### GET /api/auth/verify
Verify JWT token.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "user_id": "user_1234567890",
  "username": "johndoe",
  "message": "Token is valid"
}
```

#### GET /api/auth/profile
Get user profile.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "user_id": "user_1234567890",
  "username": "johndoe",
  "profile": {
    "email": "user@example.com",
    "role": "user",
    "created": "2024-01-01"
  }
}
```

## Security Features

| Feature | Implementation |
|---------|----------------|
| **ECC Cryptography** | secp256k1 curve with constant-time operations |
| **Password Hashing** | Argon2 + BLAKE3 hybrid approach |
| **Token Signing** | ES256 (ECDSA) signatures |
| **Session Security** | ECC-derived session keys |
| **Cache Security** | LRU with automatic expiration |
| **Timing Attacks** | Constant-time comparison operations |

## Performance

- **LRU Caching**: 5-minute TTL for token verification
- **Async Operations**: Non-blocking cryptographic operations
- **Memory Safety**: Rust ownership prevents memory corruption
- **Zero-Cost Abstractions**: High performance with no runtime overhead

## Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks:

```bash
cargo bench
```

## Example Application

See `src/main.rs` for a complete example application with all endpoints.

## Dependencies

- `actix-web` - Web framework
- `actix-web-httpauth` - HTTP authentication middleware
- `serde` - Serialization
- `jsonwebtoken` - JWT token handling
- `ring` - Cryptography (ECC)
- `argon2` - Password hashing
- `blake3` - Additional hashing
- `lru` - LRU caching
- `tokio` - Async runtime
- `chrono` - Date/time handling
- `base64` - Base64 encoding

## Project Structure

```
src/
├── auth.rs          # Core ECC authentication logic
└── main.rs          # Actix Web application and routes
Cargo.toml           # Dependencies and configuration
README.md           # Documentation
```

## Building and Running

```bash
# Build the project
cargo build --release

# Run the application
cargo run --release
```

The server will start on `http://localhost:8080`.

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request