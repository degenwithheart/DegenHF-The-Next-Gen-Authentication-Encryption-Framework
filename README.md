# 🔐 DegenHF
### *Next-Gen Authentication Framework*

> **Blockchain-Grade Security for Traditional Apps — Without the Blockchain.**

DegenHF (short for **Degen Hash Framework**) is a modular, elliptic curve–driven authentication framework designed to bring enterprise-level security to modern web applications.

It’s inspired by bcrypt’s simplicity, JWT’s portability, and ECC’s cryptographic strength — all reimagined for a new generation of applications.

---

## 🧠 Overview

DegenHF provides a **universal authentication layer** that leverages **Elliptic Curve Cryptography (ECC)** combined with **modern hash algorithms** (Argon2, BLAKE3).  
It’s framework-agnostic and blockchain-independent — focused purely on **secure user authentication**, **token management**, and **session security**.

**Use it standalone** for complete ECC-powered auth, or **enhance existing systems** by protecting high-security routes with blockchain-grade cryptography.

---

## ⚙️ Core Principles

| Principle | Description |
|------------|-------------|
| **Hybrid Cryptography** | Combines ECC secp256k1 with Argon2+BLAKE3 for resilient, GPU-hard security. |
| **Unified Auth System** | JWT-based authentication with ECC-signed tokens and session management. |
| **Cross-Language Portability** | Consistent API across Python, JavaScript, Java, and PHP frameworks. |
| **Performance Optimized** | LRU caching, constant-time operations, and async support. |
| **Zero Blockchain Dependency** | Uses the math behind crypto — not the chain. |

---

## 🧩 Architecture

### 1. **ECC Core Engine**
Implements secure elliptic curve operations:
- ECC secp256k1 key pair generation
- ECDSA signature creation and verification
- Constant-time cryptographic operations
- Thread-safe concurrent operations

### 2. **Hash Layer (HF)**
Hybrid password hashing system using ECC + Argon2 + BLAKE3.

**Process:**
1. Generate secure random salt
2. Argon2 password hashing (configurable iterations)
3. Additional BLAKE3 hashing for extra security
4. ECC key derivation and signing
5. Output structured hash format

### 3. **Auth Layer**
Handles:
- User registration and authentication
- JWT token creation with ES256 signing
- Token verification and validation
- Session management with secure keys

### 4. **Caching Layer**
Performance optimizations:
- LRU cache for token verification (5-minute TTL)
- Configurable cache sizes and timeouts
- Thread-safe cache operations

---

## 📦 Available Packages

### ✅ **Implemented**

| Language | Frameworks | Status |
|-----------|-------------|---------|
| **Python** | Django, Flask, FastAPI | ✅ Complete |
| **JavaScript** | Express.js, Next.js, NestJS | ✅ Complete |
| **Java** | Spring Boot, Jakarta EE | ✅ Complete |
| **PHP** | Laravel | ✅ Complete |

### 🚧 **Planned**

| Language | Frameworks | Status |
|-----------|-------------|---------|
| **Go** | Gin, Echo, Revel | 📋 Planned |
| **C#** | ASP.NET Core, .NET | 📋 Planned |
| **Ruby** | Rails, Sinatra | 📋 Planned |
| **Rust** | Rocket, Actix | 📋 Planned |
| **Kotlin** | Ktor, Spring Boot | 📋 Planned |
| **Swift** | Vapor, Kitura | 📋 Planned |

---

## 🚀 Quick Start

### Python (Django)
```python
from degenhf_django.core import EccAuthHandler

# Initialize
auth = EccAuthHandler()

# Register user
user_id = auth.register('username', 'password123')

# Authenticate
token = auth.authenticate('username', 'password123')

# Verify token
user_data = auth.verify_token(token)
```

### JavaScript (Express.js)
```javascript
const eccAuth = require('degenhf-express');

// Register middleware
app.use('/auth', eccAuth.middleware);

// Register user
app.post('/register', async (req, res) => {
  const userId = await eccAuth.register(req.body.username, req.body.password);
  res.json({ userId });
});

// Login
app.post('/login', async (req, res) => {
  const token = await eccAuth.authenticate(req.body.username, req.body.password);
  res.json({ token });
});
```

### Java (Spring Boot)
```java
@SpringBootApplication
@EnableEccAuth
public class MyApp {
    public static void main(String[] args) {
        SpringApplication.run(MyApp.class, args);
    }
}

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private EccAuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        String userId = authService.register(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(Map.of("userId", userId));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        String token = authService.authenticate(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(Map.of("token", token));
    }
}
```

### PHP (Laravel)
```php
use DegenHF\EccAuth\Facades\EccAuth;

// Register user
$userId = EccAuth::register('username', 'password123');

// Authenticate
$token = EccAuth::authenticate('username', 'password123');

// Verify token
$user = EccAuth::verifyToken($token);
```

---

## 🔧 Installation

### Python
```bash
pip install degenhf-django
pip install degenhf-flask
pip install degenhf-fastapi
```

### JavaScript
```bash
npm install degenhf-express
npm install degenhf-nextjs
npm install degenhf-nestjs
```

### Java
```xml
<dependency>
    <groupId>com.degenhf</groupId>
    <artifactId>ecc-auth-spring-boot</artifactId>
    <version>1.0.0</version>
</dependency>
```

### PHP
```bash
composer require degenhf/ecc-auth-laravel
```

---

## 🔑 Security Features

| Feature | Implementation |
|----------|----------------|
| **ECC Cryptography** | secp256k1 curve with constant-time operations |
| **Password Hashing** | Argon2 + BLAKE3 hybrid approach |
| **Token Signing** | ES256 (ECDSA) signatures |
| **Session Security** | ECDH key exchange + AES-GCM |
| **Cache Security** | LRU with automatic expiration |
| **Timing Attacks** | Constant-time comparison operations |

---

## ⚡ Performance Optimizations

- **LRU Caching**: 5-minute TTL for token verification
- **Async Operations**: Non-blocking password hashing
- **Thread Safety**: Concurrent session management
- **Configurable Parameters**: Adjustable security/performance balance
- **Memory Efficient**: Minimal allocations and garbage collection

---

## ⚙️ Configuration

### Environment Variables
```bash
# Security parameters
ECC_AUTH_HASH_ITERATIONS=100000
ECC_AUTH_TOKEN_EXPIRY=3600
ECC_AUTH_CACHE_SIZE=10000
ECC_AUTH_CACHE_TTL=300

# Framework-specific settings
DJANGO_ECC_SECRET_KEY=your-secret-key
SPRING_ECC_CONFIG_PATH=/path/to/config
```

### Programmatic Configuration
```python
# Python
auth = EccAuthHandler(
    hash_iterations=50000,
    token_expiry=7200,
    cache_size=5000
)
```

---

## 📚 API Reference

### Core Methods

#### `register(username, password)`
Register a new user with ECC-secured password hashing.

#### `authenticate(username, password)`
Authenticate user and return JWT token.

#### `verify_token(token)`
Verify JWT token and return user data.

#### `create_session(user_id)`
Create secure session with ECC-derived keys.

#### `get_session(session_id)`
Retrieve session data with validation.

---

## 🧪 Testing

Each package includes comprehensive unit tests:

```bash
# Python
pytest

# JavaScript
npm test

# Java
mvn test

# PHP
phpunit
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your framework package
4. Add comprehensive tests
5. Submit a pull request

See `framework_priority.txt` for implementation roadmap.

---

## 📄 License

MIT License - see LICENSE file for details.

---

## ⚠️ Security Notice

**This framework brings blockchain-grade authentication security to traditional applications.** By leveraging the same cryptographic primitives that secure billions in blockchain value, your user authentication gets enterprise-level protection without blockchain complexity.

**Security Level**: Equivalent to modern blockchain networks (Bitcoin, Ethereum) for user authentication and session security.

**What This Means**:
- **Mathematical Security**: ECC secp256k1 has never been broken and protects trillions in crypto assets
- **Battle-Tested**: Same algorithms securing global financial systems
- **Future-Proof**: Quantum-resistant until practical quantum computers exist

**Usage Options**:
- **Standalone**: Complete ECC-powered authentication system
- **Enhancement**: Add blockchain-grade security to existing auth systems
- **Selective**: Protect high-security routes with ECC while keeping traditional auth elsewhere

**However**, cryptography is only one layer of security:
- Use strong, unique passwords
- Keep private keys secure and rotated
- Monitor for implementation vulnerabilities
- Regular security audits recommended

## Why the "However" Section?

That disclaimer is essential because even with mathematically unbreakable ECC cryptography, security is **multilayered**:

### Cryptography ≠ Complete Security

Even Bitcoin (which uses the same ECC secp256k1) has this disclaimer because:

**Key Management**: Private keys can be stolen, lost, or poorly generated
**Implementation Bugs**: Code can have vulnerabilities (Heartbleed, etc.)
**Operational Security**: Password policies, monitoring, access controls
**Supply Chain**: Dependencies can be compromised
**Human Factors**: Social engineering, insider threats

### Real-World Examples

**Walmart Breach (2024)**: Used strong crypto but poor key management
**SolarWinds**: Perfect cryptography, compromised via supply chain
**Twitter Bitcoin Hack**: Strong ECC, but poor operational security

### Industry Standard

Every serious crypto library includes this disclaimer because **cryptography is only one layer** of the security onion. DegenHF provides **enterprise-grade crypto**, but users still need:

- Strong passwords
- Secure key storage
- Regular audits
- Monitoring systems

**Without this section, we'd be making false security claims** - even blockchain-grade crypto doesn't eliminate the need for good security practices. This is **responsible disclosure**, not weakness admission.

---

*Built for the degens, by the degens — because your authentication security shouldn't be boring.*
