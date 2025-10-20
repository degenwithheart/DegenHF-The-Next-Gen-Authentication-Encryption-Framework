# DegenHF ECC Auth - Swift Vapor

ECC-based authentication package for Swift Vapor with enhanced security and performance.

## Features

- **ECC secp256k1 Cryptography**: Blockchain-grade elliptic curve operations using CryptoKit
- **Hybrid Password Hashing**: Argon2 + BLAKE3 for GPU-hard security
- **JWT Token Management**: ES256 signed tokens with ECC keys
- **LRU Caching**: High-performance token verification caching
- **Vapor Middleware**: Seamless integration with Vapor's middleware system
- **Async/Await**: Full Swift concurrency support
- **Type Safety**: Swift's type system prevents common vulnerabilities
- **Constant-Time Operations**: Protection against timing attacks

## Installation

Since this package is currently only available from the GitHub repository, add it to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/degenwithheart/DegenHF-The-Next-Gen-Authentication-Encryption-Framework", from: "1.0.0")
]
```

## Quick Start

```swift
import Vapor
import JWT

// Configure JWT
app.jwt.signers.use(.es256(key: privateKey))

// Initialize ECC auth handler
let authOptions = EccAuthOptions(
    hashIterations: 100000,
    tokenExpiry: 86400, // 24 hours
    cacheSize: 10000,
    cacheTtl: 300 // 5 minutes
)

let authHandler = EccAuthHandler(options: authOptions)
app.storage.set(EccAuthHandlerKey.self, to: authHandler)

// Public routes
app.post("api/auth/register") { req async throws -> Response in
    let registerRequest = try req.content.decode(RegisterRequest.self)
    let userId = try authHandler.register(username: registerRequest.username, password: registerRequest.password)

    let response = Response(status: .created)
    try response.content.encode([
        "user_id": userId,
        "message": "User registered successfully"
    ])
    return response
}

app.post("api/auth/login") { req async throws -> Response in
    let loginRequest = try req.content.decode(LoginRequest.self)
    let token = try authHandler.authenticate(username: loginRequest.username, password: loginRequest.password)

    let response = Response(status: .ok)
    try response.content.encode([
        "token": token,
        "message": "Login successful"
    ])
    return response
}

// Protected routes
let protected = app.grouped(JWTMiddleware())
protected.get("api/auth/verify") { req async throws -> Response in
    let payload = try req.jwt.verify(as: UserPayload.self)

    let response = Response(status: .ok)
    try response.content.encode([
        "user_id": payload.subject.value,
        "username": payload.username,
        "message": "Token is valid"
    ])
    return response
}
```

## Configuration

```swift
import EccAuthHandler

let options = EccAuthOptions(
    hashIterations: 100000,        // Argon2 iterations
    tokenExpiry: 86400,            // JWT expiry (24 hours)
    cacheSize: 10000,              // LRU cache size
    cacheTtl: 300,                 // Cache TTL (5 minutes)
)

let authHandler = EccAuthHandler(options: options)
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

#### `register(username:password:)`
Registers a new user with ECC-secured password hashing.

#### `authenticate(username:password:)`
Authenticates user and returns JWT token.

#### `verifyToken(_:)`
Verifies JWT token and returns user data.

#### `createSession(userId:)`
Creates a secure session.

#### `getSession(sessionId:)`
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
- **Type Safety**: Swift's type system prevents runtime errors
- **Memory Safety**: Swift's ownership prevents memory corruption

## Testing

Run the test suite:

```bash
swift test
```

Run with coverage:

```bash
swift test --enable-code-coverage
```

## Example Application

See `Sources/App/Application.swift` for a complete example application with all endpoints.

## Dependencies

- `vapor` - Web framework
- `jwt` - JWT token handling
- `fluent` - ORM (for future database integration)
- `CryptoSwift` - Additional cryptography
- `swift-crypto` - Apple's cryptography framework
- `swift-log` - Logging

## Project Structure

```
Sources/
├── App/
│   ├── EccAuthHandler.swift    # Core ECC authentication logic
│   └── Application.swift       # Vapor application and routes
Tests/
└── AppTests/
    └── AppTests.swift          # Unit and integration tests
Package.swift                   # Dependencies and configuration
README.md                      # Documentation
```

## Building and Running

```bash
# Build the project
swift build

# Run the application
swift run

# Run in release mode
swift run --configuration release
```

The server will start on `http://localhost:8080`.

## Configuration

Create environment variables or use Vapor's configuration system:

```swift
// In configure.swift
if let jwtKey = Environment.get("JWT_KEY") {
    app.jwt.signers.use(.es256(key: try .loadFromPEM(jwtKey)))
}
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request