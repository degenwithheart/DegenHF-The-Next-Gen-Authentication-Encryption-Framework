# DegenHF Flask ECC Authentication Package

Enhanced Flask authentication package with ECC-based security, optimized for speed and security.

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
pip install degenhf-flask
```

## Usage

### Basic Setup

```python
from flask import Flask
from degenhf_flask import EccAuth

app = Flask(__name__)

# Configure ECC authentication
app.config['ECC_HASH_ITERATIONS'] = 100000
app.config['ECC_TOKEN_EXPIRY'] = 3600  # 1 hour
app.config['ECC_CACHE_SIZE'] = 10000
app.config['ECC_CACHE_TTL'] = 300      # 5 minutes

# Initialize auth
auth = EccAuth(app)
```

### Using the AuthHandler

```python
from degenhf_flask import EccAuthHandler

auth_handler = EccAuthHandler()

# Register user
user_id = auth_handler.register('username', 'MySecurePass123!')

# Authenticate
token = auth_handler.authenticate('username', 'MySecurePass123!')

# Verify token
user_data = auth_handler.verify_token(token)
```

### Flask Integration

```python
from flask import Flask, request, jsonify
from degenhf_flask import EccAuthHandler

app = Flask(__name__)
auth_handler = EccAuthHandler()

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        user_id = auth_handler.register(data['username'], data['password'])
        return jsonify({'user_id': user_id, 'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        token = auth_handler.authenticate(data['username'], data['password'])
        return jsonify({'token': token, 'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/api/auth/profile')
@auth_handler.token_required
def profile():
    user_data = auth_handler.get_current_user()
    return jsonify({
        'user': {
            'id': user_data['id'],
            'username': user_data['username']
        }
    })
```

## Configuration

The package supports the following Flask config variables:

- `ECC_HASH_ITERATIONS`: Number of Argon2 iterations (default: 100,000)
- `ECC_TOKEN_EXPIRY`: JWT token expiration in seconds (default: 3,600)
- `ECC_CACHE_SIZE`: LRU cache size for tokens (default: 10,000)
- `ECC_CACHE_TTL`: Cache time-to-live in seconds (default: 300)

## Security Considerations

- Passwords are hashed using Argon2id with BLAKE3 additional hashing
- ECC operations use secp256k1 for signing and Curve25519 for key exchange
- All cryptographic operations are constant-time to prevent timing attacks
- Tokens are cached with TTL to improve performance while maintaining security
- Sessions use ECDH key exchange with AES-GCM encryption

## Performance

This package is optimized for high-performance Flask applications:

- **Caching**: LRU cache for tokens reduces verification overhead
- **Thread Safety**: Safe for use in multi-threaded Flask applications
- **Memory Efficiency**: Minimal allocations and efficient data structures
- **Configurable Security**: Balance security vs performance with iteration counts

## Dependencies

- Flask >= 2.0
- cryptography
- PyJWT
- argon2-cffi
- lru-dict

## License

MIT