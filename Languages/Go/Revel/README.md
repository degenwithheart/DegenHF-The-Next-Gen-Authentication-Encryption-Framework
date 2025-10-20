# Go Revel ECC Authentication Framework

A secure authentication framework built with Go and the Revel web framework, featuring ECC secp256k1 cryptography, hybrid Argon2+BLAKE3 password hashing, and JWT authentication.

## Features

- **ECC secp256k1 Cryptography**: Elliptic curve cryptography for secure key generation and operations
- **Hybrid Password Hashing**: Argon2 memory-hard function combined with BLAKE3 cryptographic hash
- **JWT Authentication**: Secure JSON Web Tokens with configurable expiration
- **LRU Caching**: In-memory caching with 5-minute TTL for improved performance
- **Revel Framework**: Full-stack web framework with MVC architecture
- **Comprehensive Testing**: Unit and integration tests

## Security Specifications

- **Cryptography**: ECC secp256k1 with JWT HMAC-SHA256 signing
- **Password Hashing**: Argon2id (1 iteration, 64MB memory, 4 threads) + BLAKE3
- **Token Expiry**: 24 hours (configurable)
- **Cache TTL**: 5 minutes (configurable)
- **Session Management**: Stateless with JWT tokens

## Prerequisites

- Go 1.21 or higher
- Git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/degenhf/DegenHF.git
cd DegenHF/Go/Revel
```

2. Install dependencies:
```bash
go mod download
```

3. Run the application:
```bash
go run main.go
```

The server will start on `http://localhost:9000`

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
├── main.go                 # Application entry point
├── app/
│   ├── app.go             # Application initialization
│   ├── controllers/
│   │   ├── app.go        # Main app controller
│   │   └── auth.go       # Authentication controller
│   └── models/
│       └── user.go       # User data models
├── conf/
│   ├── app.conf          # Application configuration
│   └── routes            # Route definitions
└── tests/
    └── auth_test.go      # Unit and integration tests
```

## Dependencies

- **Revel**: Full-stack web framework for Go
- **decred/dcrd**: ECC secp256k1 cryptography
- **golang-jwt/jwt**: JSON Web Token handling
- **patrickmn/go-cache**: In-memory caching
- **golang.org/x/crypto**: Argon2 and BLAKE3 implementations

## Testing

Run the tests:
```bash
go test ./tests/...
```

Run with verbose output:
```bash
go test -v ./tests/...
```

Run with coverage:
```bash
go test -cover ./tests/...
```

## Configuration

The application can be configured via `conf/app.conf`:

```ini
# Server settings
http.port=9000
http.ssl=false

# Session settings
session.expires=24h

# Cache settings
cache.expires=5m

# Secret key (change in production)
app.secret=CHANGE_THIS_SECRET_KEY_IN_PRODUCTION_123456789012345678901234567890
```

## Security Considerations

1. **Production Deployment**:
   - Replace in-memory user storage with a proper database
   - Use environment variables for sensitive configuration
   - Implement proper session management and logout
   - Add rate limiting and DDoS protection
   - Use HTTPS in production

2. **Key Management**:
   - Store ECC keys securely (HSM or encrypted database)
   - Implement key rotation policies
   - Use different keys for different environments

3. **Password Policies**:
   - Enforce strong password requirements
   - Implement password history checks
   - Add account lockout mechanisms

## Performance

- **Caching**: LRU cache for token verification reduces computation overhead
- **Async Operations**: Non-blocking cryptographic operations
- **Memory Usage**: Efficient ECC operations with minimal memory footprint
- **Concurrent**: Thread-safe operations for high-throughput scenarios

## Contributing

1. Follow Go coding standards and conventions
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Ensure security best practices are maintained

## License

This project is part of the DegenHF authentication framework collection.