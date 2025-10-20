# DegenHF ECC Auth - .NET MAUI

ECC-based authentication package for .NET MAUI with enhanced security and performance.

## Features

- **ECC secp256k1 Cryptography**: Blockchain-grade elliptic curve operations using BouncyCastle
- **Hybrid Password Hashing**: Argon2 + BLAKE3 for GPU-hard security
- **JWT Token Management**: ES256 signed tokens with ECC keys
- **LRU Caching**: High-performance token verification caching
- **MAUI Integration**: Seamless integration with .NET MAUI applications
- **Cross-Platform**: Works on iOS, Android, Windows, and macOS
- **Type Safety**: C#'s type system prevents common vulnerabilities
- **Constant-Time Operations**: Protection against timing attacks

## Installation

Since this package is currently only available from the GitHub repository, add it to your `.csproj`:

```xml
<PackageReference Include="DegenHF.NET-MAUI" Version="1.0.0" />
```

## Quick Start

```csharp
using DegenHF.NET_MAUI;

// Initialize ECC auth handler
var options = new EccAuthOptions
{
    HashIterations = 100000,
    TokenExpiry = TimeSpan.FromHours(24),
    CacheSize = 10000,
    CacheTtl = TimeSpan.FromMinutes(5)
};

var authHandler = new EccAuthHandler(options);

// Register user
string userId = authHandler.Register("johndoe", "securepassword123");

// Authenticate user
string token = authHandler.Authenticate("johndoe", "securepassword123");

// Verify token
UserSession session = authHandler.VerifyToken(token);
```

## API Server Mode

Run the application as an API server:

```bash
dotnet run --api-server
```

The server will start on `https://localhost:5001`.

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
    "created_at": "2024-01-01T00:00:00.000Z",
    "last_login": "2024-01-01T00:00:00.000Z"
  }
}
```

## MAUI App Integration

```csharp
// In MauiProgram.cs
builder.Services.AddSingleton<EccAuthHandler>();

// In MainPage.xaml.cs
public partial class MainPage : ContentPage
{
    private readonly EccAuthHandler _authHandler;

    public MainPage(EccAuthHandler authHandler)
    {
        InitializeComponent();
        _authHandler = authHandler;
    }

    private void OnLoginClicked(object sender, EventArgs e)
    {
        try
        {
            var token = _authHandler.Authenticate(UsernameEntry.Text, PasswordEntry.Text);
            // Handle successful login
        }
        catch (Exception ex)
        {
            // Handle authentication error
        }
    }
}
```

## Configuration

```csharp
var options = new EccAuthOptions
{
    HashIterations = 100000,        // Argon2 iterations
    TokenExpiry = TimeSpan.FromHours(24), // JWT expiry
    CacheSize = 10000,              // LRU cache size
    CacheTtl = TimeSpan.FromMinutes(5), // Cache TTL
};

var authHandler = new EccAuthHandler(options);
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

#### `Register(username, password)`
Registers a new user with ECC-secured password hashing.

#### `Authenticate(username, password)`
Authenticates user and returns JWT token.

#### `VerifyToken(token)`
Verifies JWT token and returns user data.

#### `CreateSession(userId)`
Creates a secure session.

#### `GetSession(sessionId)`
Retrieves session data.

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
- **Memory Management**: .NET GC with optimized object allocation
- **Async Operations**: Non-blocking cryptographic operations
- **Type Safety**: C#'s type system prevents runtime errors

## Testing

Run the test suite:

```bash
dotnet test
```

Run with coverage:

```bash
dotnet test --collect:"XPlat Code Coverage"
```

## Example Application

See `MainPage.xaml` and `MainPage.xaml.cs` for a complete MAUI example application.

## Dependencies

- `Microsoft.Maui.Controls` - MAUI framework
- `Portable.BouncyCastle` - ECC cryptography
- `Konscious.Security.Cryptography.Argon2` - Password hashing
- `System.IdentityModel.Tokens.Jwt` - JWT token handling
- `Microsoft.Extensions.Caching.Memory` - LRU caching

## Project Structure

```
├── EccAuthHandler.cs      # Core ECC authentication logic
├── Program.cs             # MAUI app and API server
├── MainPage.xaml          # MAUI UI
├── MainPage.xaml.cs       # MAUI code-behind
├── Tests/
│   └── EccAuthHandlerTests.cs # Unit tests
└── DegenHF.NET-MAUI.csproj # Project configuration
```

## Building and Running

```bash
# Build the project
dotnet build

# Run MAUI app
dotnet run

# Run API server
dotnet run --api-server

# Run on specific platform
dotnet build -t:Run -f net8.0-ios
dotnet build -t:Run -f net8.0-android
```

The MAUI app will launch on your target platform, and the API server runs on `https://localhost:5001`.

## Platform-Specific Setup

### iOS
```bash
dotnet workload install ios
```

### Android
```bash
dotnet workload install android
```

### Windows
```bash
dotnet workload install windows
```

### macOS
```bash
dotnet workload install macos
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request