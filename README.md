# 🔐 DegenHF  
### *Next-Gen Authentication & Encryption Framework*

> **Beyond Hashing — Cryptography Evolved for the Degen Age.**

DegenHF (short for **Degen Hash Framework**) is a modular, elliptic curve–driven security framework designed to unify authentication, hashing, tokenization, and encryption across modern languages and frameworks.

It’s inspired by bcrypt’s simplicity, JWT’s portability, and ECC’s cryptographic strength — all reimagined for a new generation of applications.

---

## 🧠 Overview

DegenHF provides a **universal security layer** that leverages **Elliptic Curve Cryptography (ECC)** combined with **modern hash algorithms** (SHA-512, Argon2, BLAKE3).  
It’s framework-agnostic and blockchain-independent — focused purely on **authentication**, **data protection**, and **cryptographic integrity**.

---

## ⚙️ Core Principles

| Principle | Description |
|------------|-------------|
| **Hybrid Cryptography** | Combines ECC with SHA-3, Argon2, and BLAKE3 for resilient, GPU-hard security. |
| **Unified Auth System** | Role-based authentication (user, admin, system) with ECC-signed tokens. |
| **Cross-Language Portability** | One cryptographic backbone across Python, Go, Rust, JS, and more. |
| **Forward-Compatible** | Built to evolve into post-quantum hybrid encryption (ECC + Kyber). |
| **Zero Blockchain Dependency** | Uses the math behind crypto — not the chain. |

---

## 🧩 Architecture

### 1. **ECC Core Engine**
Implements secure elliptic curve operations:
- Point addition, doubling, and scalar multiplication  
- Curve validation and key generation  
- ECDH (Elliptic Curve Diffie–Hellman)  
- ECDSA-like signature creation and verification  

Supported curves (planned):
- `Custom25519` — based on 2²⁵⁵ - 19  
- `DegenP256` — custom NIST P-256 variant  

---

### 2. **Hash Layer (HF)**
Hybrid password hashing system using ECC transformations.

**Process:**
1. Derive scalar from password + salt  
2. Multiply by generator point G on custom curve  
3. Hash resulting coordinates with SHA-512 or Argon2  
4. Output bcrypt-style formatted string:

```
$degenhf$curve=custom25519$algo=argon2id$salt=[b64]$hash=[b64]
```

---

### 3. **Auth Layer**
Handles:
- Role-based authentication (user, admin, system)  
- ECC-signed JWT-like tokens  
- Token validation and key rotation  
- Optional AES-encrypted cookie/session sealing  

---

### 4. **Encryption Suite**
ECC-based encryption/decryption powered by ECDH + AES-GCM.

Example (conceptual):
```python
encrypt(data, public_key)
decrypt(data, private_key)
```

This allows shared secret derivation for secure communication between systems, without shared passwords.

---

### 5. **Session & Token Layer**
Implements:
- Secure session lifecycle  
- ECC-derived session keys  
- Token revocation and re-signing  
- Optional biometric → ECC hash binding  

---

## 💡 Conceptual API Examples

### **Python**
```python
from degenhf import hash_password, verify_password, sign_token

hash = hash_password("hunter2")
assert verify_password("hunter2", hash)

token = sign_token({"user": "admin"})
```

### **Node.js**
```js
import { hashPassword, verifyPassword, encrypt, decrypt } from 'degenhf';

const hash = await hashPassword('hunter2');
const valid = await verifyPassword('hunter2', hash);
const enc = await encrypt('secret message', publicKey);
```

### **Rust**
```rust
use degenhf::crypto::{hash_password, verify_password};

let hash = hash_password("hunter2");
let valid = verify_password("hunter2", &hash);
```

---

## 🌍 Framework Compatibility

| Language | Frameworks |
|-----------|-------------|
| **Python** | Django, Flask, FastAPI |
| **Go** | Gin, Echo, Revel |
| **JavaScript / TypeScript** | Express, Next.js, NestJS |
| **Java** | Spring Boot, Jakarta EE |
| **C#** | ASP.NET Core, .NET |
| **PHP** | Laravel, Symfony |
| **Ruby** | Rails, Sinatra |
| **Rust** | Rocket, Actix |
| **Kotlin** | Ktor, Spring Boot |
| **Swift** | Vapor, Kitura |

---

## 🔑 Security Stack

| Component | Role |
|------------|------|
| **ECC Hashing** | Irreversible password transformations |
| **ECDH** | Shared secret derivation for encryption |
| **AES-GCM** | Fast, symmetric data encryption |
| **ECC Signatures** | Token signing and verification |
| **Argon2 Integration** | GPU/ASIC-resistant password hardening |
| **Salt + Curve ID** | Built-in replay and curve collision prevention |
