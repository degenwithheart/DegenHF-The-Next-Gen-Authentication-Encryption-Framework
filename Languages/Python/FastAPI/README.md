# DegenHF FastAPI ECC Authentication Package

Enhanced FastAPI authentication package with ECC-based security, optimized for speed and security.

## Features

- **ECC Authentication**: secp256k1/Curve25519 cryptography with optimized operations
- **Enhanced Security**: Argon2+BLAKE3 password hashing with configurable iterations
- **Token Management**: ECC-signed JWT tokens with LRU caching and TTL
- **Session Security**: ECDH+AES-GCM session encryption
- **Performance Optimizations**:
  - LRU caching with configurable size and TTL (5-minute default)
  - Constant-time operations to prevent timing attacks
  - Reduced memory allocations
  - Async/await support for high concurrency
- **Security Enhancements**:
  - Enhanced salt generation
  - Timing attack protection
  - Additional input validations
  - Configurable security parameters

## Installation

```bash
pip install degenhf-fastapi
```

## Usage

### Basic Setup

```python
from fastapi import FastAPI
from degenhf_fastapi import EccAuthHandler

app = FastAPI()

# Configure ECC authentication
auth_config = {
    'hash_iterations': 100000,
    'token_expiry': 3600,  # 1 hour
    'cache_size': 10000,
    'cache_ttl': 300,      # 5 minutes
}

auth_handler = EccAuthHandler(**auth_config)
```

### Using the AuthHandler

```python
from degenhf_fastapi import EccAuthHandler

auth_handler = EccAuthHandler()

# Register user
user_id = await auth_handler.register('username', 'MySecurePass123!')

# Authenticate
token = await auth_handler.authenticate('username', 'MySecurePass123!')

# Verify token
user_data = await auth_handler.verify_token(token)
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from degenhf_fastapi import EccAuthHandler, get_current_user

app = FastAPI()
auth_handler = EccAuthHandler()

@app.post("/api/auth/register")
async def register(username: str, password: str):
    try:
        user_id = await auth_handler.register(username, password)
        return {"user_id": user_id, "status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login")
async def login(username: str, password: str):
    try:
        token = await auth_handler.authenticate(username, password)
        return {"token": token, "status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/api/auth/profile")
async def profile(current_user: dict = Depends(get_current_user)):
    return {
        "user": {
            "id": current_user["id"],
            "username": current_user["username"]
        }
    }
```

## Configuration

The EccAuthHandler constructor accepts the following parameters:

- `hash_iterations`: Number of Argon2 iterations (default: 100,000)
- `token_expiry`: JWT token expiration in seconds (default: 3,600)
- `cache_size`: LRU cache size for tokens (default: 10,000)
- `cache_ttl`: Cache time-to-live in seconds (default: 300)

## Security Considerations

- Passwords are hashed using Argon2id with BLAKE3 additional hashing
- ECC operations use secp256k1 for signing and Curve25519 for key exchange
- All cryptographic operations are constant-time to prevent timing attacks
- Tokens are cached with TTL to improve performance while maintaining security
- Sessions use ECDH key exchange with AES-GCM encryption

## Performance

This package is optimized for high-performance FastAPI applications:

- **Async Support**: Native async/await support for high concurrency
- **Caching**: LRU cache for tokens reduces verification overhead
- **Memory Efficiency**: Minimal allocations and efficient data structures
- **Configurable Security**: Balance security vs performance with iteration counts

## Dependencies

- FastAPI >= 0.68
- cryptography
- PyJWT
- argon2-cffi
- lru-dict

## License

MIT