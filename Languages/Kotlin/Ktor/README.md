# DegenHF ECC Auth - Kotlin Ktor

ECC-based authentication package for Kotlin Ktor with enhanced security and performance.

## Features

- **ECC secp256k1 Cryptography**: Blockchain-grade elliptic curve operations
- **Hybrid Password Hashing**: Argon2 + BLAKE3 for GPU-hard security
- **JWT Token Management**: ES256 signed tokens with ECC keys
- **LRU Caching**: High-performance token verification caching
- **Ktor Middleware**: Seamless integration with Ktor authentication
- **Kotlin Coroutines**: Full async support with Kotlin's coroutine system
- **Type Safety**: Kotlin's type system prevents common vulnerabilities
- **Constant-Time Operations**: Protection against timing attacks

## Installation

Since this package is currently only available from the GitHub repository, add it to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.degenhf:degenhf-ktor:1.0.0")
}
```

## Quick Start

```kotlin
import com.degenhf.auth.EccAuthHandler
import com.degenhf.auth.EccAuthOptions
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.routing.*
import java.time.Duration

fun Application.module() {
    // Initialize ECC auth handler
    val authOptions = EccAuthOptions(
        hashIterations = 100000,
        tokenExpiry = Duration.ofHours(24),
        cacheSize = 10000,
        cacheTtl = Duration.ofMinutes(5)
    )

    val authHandler = EccAuthHandler(authOptions)

    // Configure JWT authentication
    install(Authentication) {
        jwt("auth-jwt") {
            verifier(JwtConfig.verifier)
            validate { credential ->
                if (credential.payload.getClaim("username").asString() != null) {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }
        }
    }

    routing {
        // Public routes
        post("/api/auth/register") {
            val request = call.receive<RegisterRequest>()
            val userId = authHandler.register(request.username, request.password)
            call.respond(HttpStatusCode.Created, mapOf("user_id" to userId))
        }

        post("/api/auth/login") {
            val request = call.receive<LoginRequest>()
            val token = authHandler.authenticate(request.username, request.password)
            call.respond(HttpStatusCode.OK, mapOf("token" to token))
        }

        // Protected routes
        authenticate("auth-jwt") {
            get("/api/protected") {
                val principal = call.principal<JWTPrincipal>()!!
                val username = principal.payload.getClaim("username").asString()
                call.respond(HttpStatusCode.OK, mapOf("message" to "Hello, $username!"))
            }
        }
    }
}
```

## Configuration

```kotlin
import com.degenhf.auth.EccAuthOptions
import java.time.Duration

val options = EccAuthOptions(
    hashIterations = 100000,        // Argon2 iterations
    tokenExpiry = Duration.ofHours(24), // JWT expiry
    cacheSize = 10000,              // LRU cache size
    cacheTtl = Duration.ofMinutes(5), // Cache TTL
)

val authHandler = EccAuthHandler(options)
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

#### `register(username, password)`
Registers a new user with ECC-secured password hashing.

#### `authenticate(username, password)`
Authenticates user and returns JWT token.

#### `verifyToken(token)`
Verifies JWT token and returns user data.

#### `createSession(userId)`
Creates a secure session.

#### `getSession(sessionId)`
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
- **Type Safety**: Kotlin's type system prevents runtime errors
- **Memory Safety**: JVM garbage collection and bounds checking

## Testing

Run the test suite:

```bash
./gradlew test
```

Run with coverage:

```bash
./gradlew test jacocoTestReport
```

## Example Application

See `src/main/kotlin/com/degenhf/auth/Application.kt` for a complete example application with all endpoints.

## Dependencies

- `ktor-server-core` - Web framework
- `ktor-server-netty` - Netty server engine
- `ktor-server-auth-jwt` - JWT authentication
- `bouncycastle` - ECC cryptography
- `argon2-jvm` - Password hashing
- `BLAKE3` - Additional hashing
- `jjwt` - JWT token handling
- `caffeine` - LRU caching
- `jackson` - JSON serialization

## Project Structure

```
src/
├── main/kotlin/com/degenhf/auth/
│   ├── EccAuthHandler.kt    # Core ECC authentication logic
│   └── Application.kt       # Ktor application and routes
└── test/kotlin/com/degenhf/auth/
    └── EccAuthHandlerTest.kt # Unit tests
build.gradle.kts             # Dependencies and configuration
README.md                   # Documentation
```

## Building and Running

```bash
# Build the project
./gradlew build

# Run the application
./gradlew run

# Create fat JAR
./gradlew shadowJar
```

The server will start on `http://localhost:8080`.

## Configuration

Create an `application.conf` file for Ktor configuration:

```hocon
ktor {
    deployment {
        port = 8080
        host = "0.0.0.0"
    }
    application {
        modules = [ com.degenhf.auth.ApplicationKt.module ]
    }
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