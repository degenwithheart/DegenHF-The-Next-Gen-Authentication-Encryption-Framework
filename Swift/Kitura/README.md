# Swift Kitura ECC Authentication Framework

A secure authentication framework built with Swift and the Kitura web framework, featuring ECC secp256k1 cryptography, hybrid Argon2+BLAKE3 password hashing, and JWT authentication.

## Features

- **ECC secp256k1 Cryptography**: Elliptic curve cryptography for secure key generation and operations
- **Hybrid Password Hashing**: Argon2 memory-hard function combined with BLAKE3 cryptographic hash
- **JWT Authentication**: Secure JSON Web Tokens with configurable expiration
- **Kitura Framework**: IBM's server-side Swift web framework
- **CORS Support**: Cross-origin resource sharing configuration
- **Comprehensive Testing**: Unit tests with XCTest

## Security Specifications

- **Cryptography**: ECC secp256k1 with JWT HMAC-SHA256 signing
- **Password Hashing**: Argon2id + BLAKE3 (simplified for demo)
- **Token Expiry**: 24 hours (configurable)
- **Session Management**: Stateless with JWT tokens
- **CORS**: Configured for cross-origin requests

## Prerequisites

- Swift 5.9 or higher
- macOS 13.0 or higher
- Xcode 15.0 or higher (optional, for development)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/degenhf/DegenHF.git
cd DegenHF/Swift/Kitura
```

2. Build the project:
```bash
swift build
```

3. Run the application:
```bash
swift run
```

The server will start on `http://localhost:8080`

## API Endpoints

### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "userId": "user_1234567890_123"
}
```

### Authenticate User
```http
POST /api/auth/authenticate
Content-Type: application/json

{
  "username": "johndoe",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Authentication successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Verify Token
```http
POST /api/auth/verify
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Token is valid",
  "userId": "user_1234567890_123",
  "username": "johndoe",
  "expiresAt": "2024-01-15T10:30:00Z"
}
```

### Get User Profile
```http
GET /api/auth/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```json
{
  "success": true,
  "message": "Profile retrieved successfully",
  "profile": {
    "userId": "user_1234567890_123",
    "username": "johndoe",
    "createdAt": "2024-01-14T10:30:00Z",
    "lastLogin": "2024-01-14T10:35:00Z"
  }
}
```

### Health Check
```http
GET /api/auth/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "ecc-auth"
}
```

## Project Structure

```
├── Package.swift                    # Swift Package Manager configuration
├── Sources/
│   └── DegenHF-Kitura/
│       └── main.swift             # Main application and auth handler
└── Tests/
    └── DegenHF-KituraTests/
        └── DegenHF_KituraTests.swift # Unit tests
```

## Dependencies

- **Kitura**: IBM's server-side Swift web framework
- **Kitura-CORS**: CORS middleware for Kitura
- **Swift-JWT**: JSON Web Token handling
- **Kitura-Session**: Session management
- **SwiftyJSON**: JSON parsing and serialization
- **swift-crypto**: Apple's cryptography framework
- **BigInt**: Arbitrary-precision arithmetic
- **CryptoSwift**: Cryptographic functions

## Testing

Run the tests:
```bash
swift test
```

Run with verbose output:
```bash
swift test -v
```

## Configuration

The application can be configured by modifying the constants in `main.swift`:

```swift
// Server port
Kitura.addHTTPServer(onPort: 8080, with: router)

// CORS settings
let cors = CORS(options: Options(
    allowedOrigin: .all,
    allowedHeaders: ["Content-Type", "Authorization"],
    allowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    maxAge: 3600
))
```

## Security Considerations

1. **Production Deployment**:
   - Replace in-memory user storage with a proper database
   - Use environment variables for sensitive configuration
   - Implement proper session management and logout
   - Add rate limiting and DDoS protection
   - Use HTTPS in production

2. **Cryptographic Implementation**:
   - The current implementation uses simplified crypto for demo purposes
   - In production, use proper ECC secp256k1 implementation
   - Implement full Argon2 and BLAKE3 algorithms
   - Use hardware security modules (HSM) for key storage

3. **Password Policies**:
   - Enforce strong password requirements
   - Implement password history checks
   - Add account lockout mechanisms

## Performance

- **Memory Usage**: Efficient data structures with minimal memory footprint
- **Concurrent**: Thread-safe operations for high-throughput scenarios
- **Caching**: In-memory user storage (replace with Redis/database in production)

## Contributing

1. Follow Swift coding standards and conventions
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Ensure security best practices are maintained

## License

This project is part of the DegenHF authentication framework collection.