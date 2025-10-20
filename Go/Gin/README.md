# DegenHF ECC Auth - Gin Framework

ECC-based authentication package for Go using the Gin web framework with enhanced security and performance.

## Features

- **ECC secp256k1 Cryptography**: Blockchain-grade elliptic curve operations
- **Hybrid Password Hashing**: Argon2 + BLAKE3 for GPU-hard security
- **JWT Token Management**: ES256 signed tokens with ECC keys
- **LRU Caching**: High-performance token verification caching
- **Gin Middleware**: Seamless integration with Gin web framework
- **Thread-Safe**: Concurrent session management
- **Constant-Time Operations**: Protection against timing attacks

## Installation

Since this package is currently only available from the GitHub repository, install it using Go modules:

```bash
go get github.com/degenwithheart/DegenHF/Go/Gin
```

## Quick Start

```go
package main

import (
    "github.com/degenwithheart/DegenHF/Go/Gin/degenhf"
    "github.com/gin-gonic/gin"
)

func main() {
    // Initialize with default config
    auth, err := degenhf.NewEccAuthHandler(nil)
    if err != nil {
        panic(err)
    }

    r := gin.Default()

    // Public routes
    r.POST("/register", auth.RegisterHandler)
    r.POST("/login", auth.LoginHandler)

    // Protected routes
    protected := r.Group("/api")
    protected.Use(auth.GinMiddleware())
    {
        protected.GET("/profile", auth.ProfileHandler)
        protected.GET("/verify", auth.VerifyHandler)
    }

    r.Run(":8080")
}
```

## Configuration

```go
config := &degenhf.AuthConfig{
    HashIterations: 100000,        // Argon2 iterations
    TokenExpiry:    24 * time.Hour, // JWT expiry
    CacheSize:      10000,         // LRU cache size
    CacheTTL:       5 * time.Minute, // Cache TTL
}

auth, err := degenhf.NewEccAuthHandler(config)
```

## API Reference

### Core Methods

#### `NewEccAuthHandler(config *AuthConfig) (*EccAuthHandler, error)`
Creates a new ECC authentication handler.

#### `Register(username, password string) (string, error)`
Registers a new user and returns user ID.

#### `Authenticate(username, password string) (string, error)`
Authenticates user and returns JWT token.

#### `VerifyToken(token string) (map[string]interface{}, error)`
Verifies JWT token and returns user data.

#### `CreateSession(userID string) (string, error)`
Creates a secure session.

#### `GetSession(sessionID string) (map[string]interface{}, error)`
Retrieves session data.

### Gin Handlers

#### `RegisterHandler(c *gin.Context)`
Handles user registration (POST /register).

#### `LoginHandler(c *gin.Context)`
Handles user login (POST /login).

#### `VerifyHandler(c *gin.Context)`
Verifies token (GET /api/verify).

#### `ProfileHandler(c *gin.Context)`
Returns user profile (GET /api/profile).

#### `GinMiddleware() gin.HandlerFunc`
Returns authentication middleware for protected routes.

## API Endpoints

### Public Endpoints

#### POST /register
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

#### POST /login
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

#### GET /api/verify
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

#### GET /api/profile
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
- **Thread Safety**: Concurrent session management
- **Memory Efficient**: Minimal allocations and garbage collection

## Testing

Run the test suite:

```bash
go test ./...
```

Run benchmarks:

```bash
go test -bench=. ./...
```

## Example Application

See `main.go` for a complete example application with all endpoints.

## Dependencies

- `github.com/gin-gonic/gin` - Web framework
- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `github.com/decred/dcrd/dcrec/secp256k1/v4` - ECC cryptography
- `golang.org/x/crypto` - Argon2 and BLAKE3 hashing
- `github.com/hashicorp/golang-lru/v2` - LRU caching

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request