# DegenHF Express.js ECC Authentication Package

Enhanced Express.js authentication middleware with ECC-based security, optimized for speed and security.

## Features

- **ECC Authentication**: secp256k1/Curve25519 cryptography with optimized operations
- **Enhanced Security**: Argon2+BLAKE3 password hashing with configurable iterations
- **Token Management**: ECC-signed JWT tokens with LRU caching and TTL
- **Session Security**: ECDH+AES-GCM session encryption
- **Performance Optimizations**:
  - LRU caching with configurable size and TTL (5-minute default)
  - Constant-time operations to prevent timing attacks
  - Reduced memory allocations
  - Non-blocking async operations
- **Security Enhancements**:
  - Enhanced salt generation
  - Timing attack protection
  - Additional input validations
  - Configurable security parameters

## Installation

```bash
npm install degenhf-express-ecc-auth
```

## Usage

### Basic Setup

```javascript
const express = require('express');
const { EccAuthHandler } = require('degenhf-express-ecc-auth');

const app = express();
app.use(express.json());

// Configure ECC authentication
const authConfig = {
  hashIterations: 100000,
  tokenExpiry: 3600,    // 1 hour
  cacheSize: 10000,
  cacheTTL: 300         // 5 minutes
};

const authHandler = new EccAuthHandler(authConfig);
```

### Using the AuthHandler

```javascript
// Register user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const userId = await authHandler.register(username, password);
    res.json({ userId, status: 'success' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Authenticate
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const token = await authHandler.authenticate(username, password);
    res.json({ token, status: 'success' });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});
```

### Middleware Integration

```javascript
// JWT verification middleware
const jwtAuth = authHandler.jwtAuth();

// Protected routes
app.get('/api/profile', jwtAuth, (req, res) => {
  res.json({
    user: req.user,
    message: 'Profile accessed successfully'
  });
});

// Session management
app.post('/api/session', jwtAuth, async (req, res) => {
  try {
    const session = await authHandler.createSession(req.user.id);
    res.json({ session, status: 'success' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

## Configuration

The EccAuthHandler constructor accepts the following options:

- `hashIterations`: Number of Argon2 iterations (default: 100,000)
- `tokenExpiry`: JWT token expiration in seconds (default: 3,600)
- `cacheSize`: LRU cache size for tokens (default: 10,000)
- `cacheTTL`: Cache time-to-live in seconds (default: 300)

## Security Considerations

- Passwords are hashed using Argon2id with BLAKE3 additional hashing
- ECC operations use secp256k1 for signing and Curve25519 for key exchange
- All cryptographic operations are constant-time to prevent timing attacks
- Tokens are cached with TTL to improve performance while maintaining security
- Sessions use ECDH key exchange with AES-GCM encryption

## Performance

This package is optimized for high-performance Express.js applications:

- **Async Operations**: Non-blocking async/await support
- **Caching**: LRU cache for tokens reduces verification overhead
- **Memory Efficiency**: Minimal allocations and efficient data structures
- **Configurable Security**: Balance security vs performance with iteration counts

## Dependencies

- express >= 4.17
- jsonwebtoken
- argon2
- blake3
- lru-cache
- crypto

## License

MIT