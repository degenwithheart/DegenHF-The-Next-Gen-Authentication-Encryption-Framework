# Ruby Sinatra ECC Authentication Framework

A secure authentication framework built with Ruby and the Sinatra web framework, featuring ECC secp256k1 cryptography, hybrid Argon2+BLAKE3 password hashing, and JWT authentication.

## Features

- **ECC secp256k1 Cryptography**: Elliptic curve cryptography for secure key generation and operations
- **Hybrid Password Hashing**: Argon2 memory-hard function combined with BLAKE3 cryptographic hash
- **JWT Authentication**: Secure JSON Web Tokens with configurable expiration
- **Sinatra Framework**: Lightweight Ruby web framework
- **CORS Support**: Cross-origin resource sharing configuration
- **Comprehensive Testing**: RSpec tests with coverage reporting

## Security Specifications

- **Cryptography**: ECC secp256k1 with JWT HMAC-SHA256 signing
- **Password Hashing**: Argon2id + BLAKE3 (simplified for demo)
- **Token Expiry**: 24 hours (configurable)
- **Session Management**: Stateless with JWT tokens
- **CORS**: Configured for cross-origin requests

## Prerequisites

- Ruby 3.0 or higher
- Bundler gem

## Installation

1. Clone the repository:
```bash
git clone https://github.com/degenhf/DegenHF.git
cd DegenHF/Ruby/Sinatra
```

2. Install dependencies:
```bash
bundle install
```

3. Run the application:
```bash
bundle exec rackup
```

The server will start on `http://localhost:9292`

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

## Project Structure

```
├── Gemfile                 # Ruby dependencies
├── Rakefile               # Rake tasks
├── config.ru              # Rack configuration
├── app.rb                 # Main Sinatra application
└── spec/
    ├── spec_helper.rb     # RSpec configuration
    └── auth_spec.rb       # Unit and integration tests
```

## Dependencies

- **Sinatra**: Lightweight Ruby web framework
- **sinatra-contrib**: Sinatra extensions
- **JWT**: JSON Web Token handling
- **bcrypt**: Password hashing
- **openssl**: Cryptographic operations
- **rack-cors**: CORS middleware
- **puma**: High-performance web server
- **rspec**: Testing framework
- **rack-test**: Rack testing utilities

## Testing

Run the tests:
```bash
bundle exec rspec
```

Run with coverage:
```bash
bundle exec rspec --format html --out coverage.html
```

## Configuration

The application can be configured by modifying constants in `app.rb`:

```ruby
# Token expiry (24 hours)
expiry = now + (24 * 60 * 60)

# CORS settings in config.ru
use Rack::Cors do
  allow do
    origins '*'
    resource '*',
      headers: :any,
      methods: [:get, :post, :put, :delete, :options]
  end
end
```

## Security Considerations

1. **Production Deployment**:
   - Replace in-memory user storage with a proper database
   - Use environment variables for sensitive configuration
   - Implement proper session management and logout
   - Add rate limiting and DDoS protection
   - Use HTTPS in production

2. **Cryptographic Implementation**:
   - The current implementation uses simplified crypto for demo purposes
   - In production, use proper ECC secp256k1 implementation
   - Implement full Argon2 and BLAKE3 algorithms
   - Use secure key storage mechanisms

3. **Password Policies**:
   - Enforce strong password requirements
   - Implement password history checks
   - Add account lockout mechanisms

## Performance

- **Memory Usage**: Efficient data structures with minimal memory footprint
- **Concurrent**: Thread-safe operations for high-throughput scenarios
- **Caching**: In-memory user storage (replace with Redis/database in production)

## Development

Start the development server:
```bash
bundle exec rackup
```

Or with automatic reloading:
```bash
bundle exec rerun rackup
```

## Contributing

1. Follow Ruby coding standards and conventions
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Ensure security best practices are maintained

## License

This project is part of the DegenHF authentication framework collection.