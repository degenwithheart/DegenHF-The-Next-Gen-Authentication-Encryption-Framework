# DegenHF Next.js ECC Authentication Package

Enhanced Next.js authentication package with ECC-based security, optimized for speed and security.

## Features

- **ECC Authentication**: secp256k1/Curve25519 cryptography with optimized operations
- **Enhanced Security**: Argon2+BLAKE3 password hashing with configurable iterations
- **Token Management**: ECC-signed JWT tokens with LRU caching and TTL
- **Session Security**: ECDH+AES-GCM session encryption
- **Performance Optimizations**:
  - LRU caching with configurable size and TTL (5-minute default)
  - Constant-time operations to prevent timing attacks
  - Reduced memory allocations
  - React Server Components support
- **Security Enhancements**:
  - Enhanced salt generation
  - Timing attack protection
  - Additional input validations
  - Configurable security parameters

## Installation

```bash
npm install degenhf-nextjs-ecc-auth
```

## Usage

### API Routes Setup

```javascript
// pages/api/auth/[...auth].js
import { EccAuthHandler } from 'degenhf-nextjs-ecc-auth';

const authConfig = {
  hashIterations: 100000,
  tokenExpiry: 3600,    // 1 hour
  cacheSize: 10000,
  cacheTTL: 300         // 5 minutes
};

const authHandler = new EccAuthHandler(authConfig);

export default async function handler(req, res) {
  const { action } = req.query;

  switch (action) {
    case 'register':
      if (req.method === 'POST') {
        try {
          const { username, password } = req.body;
          const userId = await authHandler.register(username, password);
          res.status(200).json({ userId, status: 'success' });
        } catch (error) {
          res.status(400).json({ error: error.message });
        }
      }
      break;

    case 'login':
      if (req.method === 'POST') {
        try {
          const { username, password } = req.body;
          const token = await authHandler.authenticate(username, password);
          res.status(200).json({ token, status: 'success' });
        } catch (error) {
          res.status(401).json({ error: error.message });
        }
      }
      break;

    default:
      res.status(404).json({ error: 'Action not found' });
  }
}
```

### Client-Side Usage

```javascript
// components/LoginForm.js
import { useState } from 'react';

export default function LoginForm() {
  const [credentials, setCredentials] = useState({ username: '', password: '' });

  const handleSubmit = async (e) => {
    e.preventDefault();

    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });

    const data = await response.json();

    if (data.status === 'success') {
      localStorage.setItem('token', data.token);
      // Redirect to protected page
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="Username"
        value={credentials.username}
        onChange={(e) => setCredentials({...credentials, username: e.target.value})}
      />
      <input
        type="password"
        placeholder="Password"
        value={credentials.password}
        onChange={(e) => setCredentials({...credentials, password: e.target.value})}
      />
      <button type="submit">Login</button>
    </form>
  );
}
```

### Protected Pages

```javascript
// pages/profile.js
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

export default function Profile() {
  const [user, setUser] = useState(null);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('token');

    if (!token) {
      router.push('/login');
      return;
    }

    // Verify token on server
    fetch('/api/auth/verify', {
      headers: { Authorization: `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(data => {
      if (data.status === 'success') {
        setUser(data.user);
      } else {
        localStorage.removeItem('token');
        router.push('/login');
      }
    });
  }, []);

  if (!user) return <div>Loading...</div>;

  return (
    <div>
      <h1>Welcome {user.username}</h1>
      <p>User ID: {user.id}</p>
    </div>
  );
}
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

This package is optimized for high-performance Next.js applications:

- **Server-Side Rendering**: Full SSR/SSG support
- **API Routes**: Optimized for Next.js API routes
- **Caching**: LRU cache for tokens reduces verification overhead
- **Memory Efficiency**: Minimal allocations and efficient data structures

## Dependencies

- next >= 12.0
- react >= 17.0
- argon2
- blake3
- jsonwebtoken
- lru-cache

## License

MIT