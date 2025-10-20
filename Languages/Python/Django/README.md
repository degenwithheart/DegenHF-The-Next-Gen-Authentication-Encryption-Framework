# DegenHF Django ECC Authentication Package

Enhanced Django authentication package with ECC-based security, optimized for speed and security.

## Features

- **ECC Authentication**: secp256k1/Curve25519 cryptography with optimized operations
- **Enhanced Security**: Argon2+BLAKE3 password hashing with configurable iterations
- **Token Management**: ECC-signed JWT tokens with LRU caching and TTL
- **Session Security**: ECDH+AES-GCM session encryption
- **Performance Optimizations**:
  - LRU caching with configurable size and TTL (5-minute default)
  - Constant-time operations to prevent timing attacks
  - Reduced memory allocations
  - Thread-safe operations
- **Security Enhancements**:
  - Enhanced salt generation
  - Timing attack protection
  - Additional input validations
  - Configurable security parameters

## Installation

```bash
pip install degenhf-django
```

## Usage

### Basic Setup

```python
# settings.py
INSTALLED_APPS = [
    # ... other apps
    'degenhf_django',
]

# Configure ECC authentication
DEGENHF_CONFIG = {
    'HASH_ITERATIONS': 100000,
    'TOKEN_EXPIRY': 3600,  # 1 hour
    'CACHE_SIZE': 10000,
    'CACHE_TTL': 300,      # 5 minutes
}
```

### Using the AuthHandler

```python
from degenhf_django.core import EccAuthHandler

# Initialize handler
auth_handler = EccAuthHandler()

# Register user
user_id = auth_handler.register('username', 'MySecurePass123!')

# Authenticate
token = auth_handler.authenticate('username', 'MySecurePass123!')

# Verify token
user_data = auth_handler.verify_token(token)
```

### Django Integration

```python
# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from degenhf_django.core import EccAuthHandler
import json

auth_handler = EccAuthHandler()

@csrf_exempt
def register_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        try:
            user_id = auth_handler.register(data['username'], data['password'])
            return JsonResponse({'user_id': user_id, 'status': 'success'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        try:
            token = auth_handler.authenticate(data['username'], data['password'])
            return JsonResponse({'token': token, 'status': 'success'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=401)
```

## Configuration

The package supports the following Django settings:

- `DEGENHF_HASH_ITERATIONS`: Number of Argon2 iterations (default: 100,000)
- `DEGENHF_TOKEN_EXPIRY`: JWT token expiration in seconds (default: 3,600)
- `DEGENHF_CACHE_SIZE`: LRU cache size for tokens (default: 10,000)
- `DEGENHF_CACHE_TTL`: Cache time-to-live in seconds (default: 300)

## Security Considerations

- Passwords are hashed using Argon2id with BLAKE3 additional hashing
- ECC operations use secp256k1 for signing and Curve25519 for key exchange
- All cryptographic operations are constant-time to prevent timing attacks
- Tokens are cached with TTL to improve performance while maintaining security
- Sessions use ECDH key exchange with AES-GCM encryption

## Performance

This package is optimized for high-performance Django applications:

- **Caching**: LRU cache for tokens reduces verification overhead
- **Thread Safety**: Safe for use in multi-threaded Django applications
- **Memory Efficiency**: Minimal allocations and efficient data structures
- **Configurable Security**: Balance security vs performance with iteration counts

## Dependencies

- Django >= 3.2
- cryptography
- PyJWT
- argon2-cffi
- lru-dict

## License

MIT