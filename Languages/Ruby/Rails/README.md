# DegenHF ECC Auth - Ruby on Rails

ECC-based authentication package for Ruby on Rails with enhanced security and performance.

## Features

- **ECC secp256k1 Cryptography**: Blockchain-grade elliptic curve operations using OpenSSL
- **Hybrid Password Hashing**: Argon2 + BLAKE3 for GPU-hard security
- **JWT Token Management**: ES256 signed tokens with ECC keys
- **LRU Caching**: High-performance token verification caching with Redis
- **Rails Middleware**: Seamless integration with Rails middleware system
- **Active Support**: Full Rails integration with logging and configuration
- **Memory Safety**: Ruby's garbage collection prevents memory corruption
- **Constant-Time Operations**: Protection against timing attacks

## Installation

Since this package is currently only available from the GitHub repository, add it to your `Gemfile`:

```ruby
gem 'degenhf-rails', git: 'https://github.com/degenwithheart/DegenHF-The-Next-Gen-Authentication-Encryption-Framework', glob: 'Ruby/Rails/lib/**/*.rb'
```

## Quick Start

```ruby
# In your Rails controller
require 'degenhf/ecc_auth_handler'

class AuthController < ApplicationController
  skip_before_action :verify_authenticity_token

  def initialize
    @auth_handler = DegenHF::EccAuthHandler.new(
      hash_iterations: 100_000,
      token_expiry: 86_400, # 24 hours
      cache_size: 10_000,
      cache_ttl: 300 # 5 minutes
    )
  end

  def register
    user_id = @auth_handler.register(params[:username], params[:password])
    render json: { user_id: user_id, message: 'User registered successfully' }, status: :created
  end

  def login
    token = @auth_handler.authenticate(params[:username], params[:password])
    render json: { token: token, message: 'Login successful' }
  end

  def verify
    token = request.headers['Authorization']&.sub('Bearer ', '')
    session = @auth_handler.verify_token(token)
    render json: { user_id: session[:user_id], username: session[:username], message: 'Token is valid' }
  end
end
```

## Configuration

```ruby
# config/initializers/degenhf.rb
require 'degenhf/ecc_auth_handler'

Rails.application.config.degenhf = {
  hash_iterations: 100_000,
  token_expiry: 86_400, # 24 hours
  cache_size: 10_000,
  cache_ttl: 300, # 5 minutes
}

# Initialize auth handler
DEGENHF_AUTH_HANDLER = DegenHF::EccAuthHandler.new(Rails.application.config.degenhf)
```

## API Reference

### Core Types

#### `DegenHF::EccAuthHandler`
Main authentication handler with ECC operations.

### Methods

#### `register(username, password)`
Registers a new user with ECC-secured password hashing.

#### `authenticate(username, password)`
Authenticates user and returns JWT token.

#### `verify_token(token)`
Verifies JWT token and returns user session.

#### `create_session(user_id)`
Creates a secure session.

#### `get_session(session_id)`
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
| **Cache Security** | Redis-backed LRU with automatic expiration |
| **Timing Attacks** | Constant-time comparison operations |

## Performance

- **Redis Caching**: 5-minute TTL for token verification
- **Connection Pooling**: Efficient Redis connection management
- **Async Operations**: Non-blocking cryptographic operations
- **Memory Management**: Ruby GC with optimized object allocation

## Testing

Run the test suite:

```bash
bundle exec rspec
```

Run with coverage:

```bash
bundle exec rspec --format html --out coverage.html
```

## Example Application

See `app/controllers/auth_controller.rb` for a complete example controller with all endpoints.

## Dependencies

- `rails` - Web framework
- `jwt` - JWT token handling
- `argon2` - Password hashing
- `openssl` - ECC cryptography
- `redis` - Caching backend
- `connection_pool` - Redis connection pooling
- `rack-cors` - CORS support

## Project Structure

```
app/
├── controllers/
│   └── auth_controller.rb    # Rails controller with auth endpoints
config/
├── application.rb            # Rails application configuration
├── routes.rb                 # API route definitions
lib/
└── degenhf/
    └── ecc_auth_handler.rb   # Core ECC authentication logic
spec/
├── spec_helper.rb           # RSpec configuration
└── degenhf/
    └── ecc_auth_handler_spec.rb # Unit tests
Gemfile                      # Dependencies
README.md                    # Documentation
```

## Building and Running

```bash
# Install dependencies
bundle install

# Create database (if using ActiveRecord)
bundle exec rails db:create db:migrate

# Run the application
bundle exec rails server

# Run in production
bundle exec rails server -e production
```

The server will start on `http://localhost:3000`.

## Configuration

Create an `application.yml` file for environment-specific settings:

```yaml
development:
  degenhf:
    hash_iterations: 10000
    token_expiry: 86400
    cache_size: 1000
    cache_ttl: 300

production:
  degenhf:
    hash_iterations: 100000
    token_expiry: 86400
    cache_size: 10000
    cache_ttl: 300
```

## Redis Setup

For production caching, ensure Redis is running:

```bash
# Install Redis
brew install redis

# Start Redis
redis-server

# Or use Docker
docker run -d -p 6379:6379 redis:alpine
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request