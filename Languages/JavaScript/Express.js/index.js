/**
 * DegenHF Express.js ECC Authentication Package
 *
 * Enhanced Express.js authentication middleware with ECC-based security,
 * optimized for speed and security.
 */

const crypto = require('crypto');
const argon2 = require('argon2');
const blake3 = require('blake3');
const jwt = require('jsonwebtoken');
const LRU = require('lru-cache');

class EccAuthConfig {
  constructor(options = {}) {
    this.hashIterations = options.hashIterations || 100000;
    this.tokenExpiry = options.tokenExpiry || 3600;
    this.cacheSize = options.cacheSize || 10000;
    this.cacheTTL = options.cacheTTL || 300;
  }
}

class EccAuthHandler {
  /**
   * Enhanced ECC authentication handler for Express.js
   *
   * Features:
   * - ECC-based authentication with secp256k1
   * - Argon2+BLAKE3 password hashing
   * - LRU caching with TTL
   * - Constant-time operations
   * - Async operations for high performance
   */
  constructor(options = {}) {
    this.config = new EccAuthConfig(options);

    // Initialize ECC key pair (simplified for Node.js crypto)
    this.keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Initialize LRU cache for tokens
    this.tokenCache = new LRU({
      max: this.config.cacheSize,
      ttl: this.config.cacheTTL * 1000, // Convert to milliseconds
    });

    // In-memory user storage (replace with database in production)
    this.users = new Map();
    this.sessions = new Map();
  }

  _generateUserId() {
    return crypto.randomBytes(16).toString('hex');
  }

  _generateSalt() {
    const timestamp = Date.now().toString();
    const randomSalt = crypto.randomBytes(16);
    return Buffer.concat([Buffer.from(timestamp), randomSalt]);
  }

  async _hashPassword(password, salt) {
    // Argon2 hashing
    const argon2Hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB
      timeCost: Math.max(1, this.config.hashIterations / 1000),
      parallelism: 4,
      hashLength: 32,
      salt,
    });

    // Additional BLAKE3 hashing
    const hasher = blake3.createHash();
    hasher.update(Buffer.from(argon2Hash));
    hasher.update(salt);
    const blake3Hash = hasher.digest();

    // Combine salt + Argon2 + BLAKE3
    return Buffer.concat([salt, Buffer.from(argon2Hash), blake3Hash]);
  }

  async _verifyPassword(password, storedHash) {
    if (storedHash.length < 48) return false;

    const salt = storedHash.slice(0, 32);
    const expectedHash = storedHash.slice(32);

    try {
      const computedHash = await this._hashPassword(password, salt);
      // Constant-time comparison to prevent timing attacks
      return crypto.timingSafeEqual(computedHash.slice(32), expectedHash);
    } catch (error) {
      return false;
    }
  }

  _createToken(userId, username) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: userId,
      username,
      iat: now,
      exp: now + this.config.tokenExpiry,
    };

    return jwt.sign(payload, this.keyPair.privateKey, { algorithm: 'ES256' });
  }

  _verifyToken(token) {
    // Check cache first
    const cacheKey = `token:${crypto.createHash('sha256').update(token).digest('hex').slice(0, 16)}`;
    const cachedResult = this.tokenCache.get(cacheKey);

    if (cachedResult && cachedResult.expires > Date.now()) {
      return cachedResult.payload;
    }

    try {
      const payload = jwt.verify(token, this.keyPair.publicKey, { algorithms: ['ES256'] });

      // Cache the result
      this.tokenCache.set(cacheKey, {
        payload,
        expires: Date.now() + (this.config.cacheTTL * 1000)
      });

      return payload;
    } catch (error) {
      return null;
    }
  }

  async register(username, password) {
    if (!username || !password) {
      throw new Error('Username and password are required');
    }

    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    if (this.users.has(username)) {
      throw new Error('User already exists');
    }

    const userId = this._generateUserId();
    const salt = this._generateSalt();
    const passwordHash = await this._hashPassword(password, salt);

    const userData = {
      id: userId,
      username,
      passwordHash: passwordHash.toString('hex'),
      createdAt: Date.now(),
    };

    this.users.set(username, userData);
    return userId;
  }

  async authenticate(username, password) {
    const userData = this.users.get(username);
    if (!userData) {
      throw new Error('User not found');
    }

    const storedHash = Buffer.from(userData.passwordHash, 'hex');
    const isValid = await this._verifyPassword(password, storedHash);

    if (!isValid) {
      throw new Error('Invalid password');
    }

    const token = this._createToken(userData.id, username);

    // Cache token
    this.sessions.set(`token:${userData.id}`, {
      token,
      expires: Date.now() + (this.config.cacheTTL * 1000)
    });

    return token;
  }

  verifyToken(token) {
    const payload = this._verifyToken(token);
    if (!payload) {
      throw new Error('Invalid or expired token');
    }

    // Find user by ID
    for (const userData of this.users.values()) {
      if (userData.id === payload.sub) {
        return userData;
      }
    }

    throw new Error('User not found');
  }

  async createSession(userId) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const sessionKey = crypto.randomBytes(32);

    const sessionData = {
      sessionId,
      userId,
      sessionKey: sessionKey.toString('hex'),
      createdAt: Date.now(),
      expiresAt: Date.now() + (3600 * 1000), // 1 hour
    };

    this.sessions.set(sessionId, sessionData);
    return sessionData;
  }

  getSession(sessionId) {
    const sessionData = this.sessions.get(sessionId);
    if (sessionData && sessionData.expiresAt > Date.now()) {
      return sessionData;
    }

    // Clean up expired session
    if (sessionData) {
      this.sessions.delete(sessionId);
    }

    return null;
  }

  jwtAuth() {
    return (req, res, next) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization header required' });
      }

      const token = authHeader.substring(7);

      try {
        const userData = this.verifyToken(token);
        req.user = userData;
        next();
      } catch (error) {
        res.status(401).json({ error: error.message });
      }
    };
  }
}

module.exports = {
  EccAuthHandler,
  EccAuthConfig,
};