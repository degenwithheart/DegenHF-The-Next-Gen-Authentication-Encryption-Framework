# DegenHF ECC Auth - ASP.NET Core

ECC-based authentication package for ASP.NET Core with enhanced security and performance.

## Features

- **ECC secp256k1 Cryptography**: Blockchain-grade elliptic curve operations
- **Hybrid Password Hashing**: Argon2 + BLAKE3 for GPU-hard security
- **JWT Token Management**: ES256 signed tokens with ECC keys
- **Memory Caching**: High-performance token verification caching
- **ASP.NET Core Middleware**: Seamless integration with ASP.NET Core pipeline
- **Thread-Safe**: Concurrent session management
- **Constant-Time Operations**: Protection against timing attacks

## Installation

Since this package is currently only available from the GitHub repository, add it using NuGet with source:

```bash
# Add the GitHub repository as a NuGet source
dotnet nuget add source https://nuget.pkg.github.com/degenwithheart/index.json -n github -u degenwithheart -p YOUR_TOKEN

# Install the package
dotnet add package DegenHF.EccAuth.AspNetCore --version 1.0.0
```

## Quick Start

```csharp
using DegenHF.EccAuth.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add ECC authentication
builder.Services.AddEccAuth();

var app = builder.Build();

// Add ECC authentication middleware
app.UseEccAuth();

app.MapControllers();
app.Run();
```

## Configuration

```csharp
using DegenHF.EccAuth;

var builder = WebApplication.CreateBuilder(args);

// Configure ECC authentication options
builder.Services.AddEccAuth(new EccAuthOptions
{
    HashIterations = 100000,
    TokenExpiry = TimeSpan.FromHours(24),
    CacheExpiry = TimeSpan.FromMinutes(5)
});

var app = builder.Build();
```

## API Reference

### Core Classes

#### `EccAuthHandler`
Main authentication handler with ECC operations.

#### `EccAuthOptions`
Configuration options for authentication.

#### `EccAuthMiddleware`
ASP.NET Core middleware for authentication.

#### `EccAuthorizeAttribute`
Attribute for protecting controllers/actions.

### Methods

#### `RegisterAsync(username, password)`
Registers a new user with ECC-secured password hashing.

#### `AuthenticateAsync(username, password)`
Authenticates user and returns JWT token.

#### `VerifyTokenAsync(token)`
Verifies JWT token and returns user data.

#### `CreateSession(userId)`
Creates a secure session.

#### `GetSession(sessionId)`
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
| **Cache Security** | Memory cache with automatic expiration |
| **Timing Attacks** | Constant-time comparison operations |

## Performance

- **Memory Caching**: 5-minute TTL for token verification
- **Async Operations**: Non-blocking cryptographic operations
- **Thread Safety**: Concurrent session management
- **Memory Efficient**: Minimal allocations and garbage collection

## Testing

Run the test suite:

```bash
dotnet test
```

## Example Application

See `Program.cs` for a complete example application with all endpoints.

## Dependencies

- `Microsoft.IdentityModel.Tokens` - JWT token handling
- `System.IdentityModel.Tokens.Jwt` - JWT implementation
- `Microsoft.Extensions.Caching.Memory` - Memory caching
- `Konscious.Security.Cryptography.Argon2` - Argon2 password hashing
- `System.Security.Cryptography` - ECC cryptography

## Project Structure

```
DegenHF.EccAuth.AspNetCore/
├── DegenHF.EccAuth/           # Core ECC authentication library
│   ├── EccAuthHandler.cs      # Main authentication logic
│   └── DegenHF.EccAuth.csproj
├── DegenHF.EccAuth.AspNetCore/ # ASP.NET Core integration
│   ├── Controllers/
│   │   └── AuthController.cs   # API controllers
│   ├── EccAuthMiddleware.cs    # Authentication middleware
│   ├── Program.cs             # Application entry point
│   └── DegenHF.EccAuth.AspNetCore.csproj
└── README.md
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request