# Kotlin Spring Boot ECC Authentication Framework

A secure authentication framework built with Kotlin and Spring Boot, featuring ECC secp256k1 cryptography, hybrid Argon2+BLAKE3 password hashing, and ES256 JWT signing.

## Features

- **ECC secp256k1 Cryptography**: Elliptic curve cryptography for secure key generation and operations
- **Hybrid Password Hashing**: Argon2 memory-hard function combined with BLAKE3 cryptographic hash
- **JWT Authentication**: ES256 signed JSON Web Tokens with configurable expiration
- **LRU Caching**: In-memory caching with 5-minute TTL for improved performance
- **Spring Security Integration**: Comprehensive security configuration with CORS support
- **RESTful API**: Clean REST endpoints for authentication operations
- **Comprehensive Testing**: Unit and integration tests with Spring Boot Test

## Security Specifications

- **Cryptography**: ECC secp256k1 with ES256 JWT signing
- **Password Hashing**: Argon2id (100,000 iterations) + BLAKE3
- **Token Expiry**: 24 hours (configurable)
- **Cache TTL**: 5 minutes (configurable)
- **Session Management**: Stateless with JWT tokens
- **CORS**: Configured for cross-origin requests

## Prerequisites

- Java 17 or higher
- Gradle 7.0+ (or use included Gradle wrapper)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/degenhf/DegenHF.git
cd DegenHF/Kotlin/SpringBoot
```

2. Build the project:
```bash
./gradlew build
```

3. Run the application:
```bash
./gradlew bootRun
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

## Configuration

The application can be configured via `application.properties` or environment variables:

```properties
# Security settings
app.auth.hash-iterations=100000
app.auth.token-expiry-hours=24
app.auth.cache-ttl-minutes=5

# Server settings
server.port=8080
```

## Project Structure

```
src/
├── main/
│   ├── kotlin/com/degenhf/auth/
│   │   ├── Application.kt              # Spring Boot main application
│   │   ├── EccAuthHandler.kt           # Core authentication logic
│   │   ├── AuthController.kt           # REST API endpoints
│   │   ├── SecurityConfig.kt           # Spring Security configuration
│   │   └── CacheConfig.kt              # Caching configuration
│   └── resources/
│       └── application.properties      # Application configuration
└── test/
    └── kotlin/com/degenhf/auth/
        └── AuthTests.kt                 # Unit and integration tests
```

## Dependencies

- **Spring Boot Web**: REST API framework
- **Spring Security**: Authentication and authorization
- **Spring Cache**: Caching support
- **BouncyCastle**: ECC cryptography provider
- **JJWT**: JSON Web Token handling
- **Argon2 JVM**: Password hashing
- **BLAKE3**: Additional cryptographic hashing
- **Jackson**: JSON serialization
- **JUnit 5**: Testing framework
- **MockMvc**: Integration testing

## Testing

Run the tests:
```bash
./gradlew test
```

Run with coverage:
```bash
./gradlew test jacocoTestReport
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

- **Caching**: LRU cache with configurable TTL reduces token verification overhead
- **Async Operations**: Non-blocking authentication operations
- **Memory Usage**: Efficient ECC operations with minimal memory footprint
- **Concurrent**: Thread-safe operations for high-throughput scenarios

## Contributing

1. Follow Kotlin coding standards
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Ensure security best practices are maintained

## License

This project is part of the DegenHF authentication framework collection.