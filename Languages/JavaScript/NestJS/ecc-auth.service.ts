/**
 * ECC Authentication Service for NestJS
 */

import { Injectable, Inject, Optional } from '@nestjs/common';
import * as crypto from 'crypto';
import * as argon2 from 'argon2';
import * as blake3 from 'blake3';
import * as jwt from 'jsonwebtoken';
import * as LRU from 'lru-cache';

export interface EccAuthModuleOptions {
  hashIterations?: number;
  tokenExpiry?: number;
  cacheSize?: number;
  cacheTTL?: number;
}

export interface UserData {
  id: string;
  username: string;
  passwordHash: string;
  createdAt: number;
}

export interface SessionData {
  sessionId: string;
  userId: string;
  sessionKey: string;
  createdAt: number;
  expiresAt: number;
}

@Injectable()
export class EccAuthService {
  private keyPair: crypto.KeyPairKeyObjectResult;
  private tokenCache: LRU<string, { payload: any; expires: number }>;
  private users: Map<string, UserData> = new Map();
  private sessions: Map<string, SessionData> = new Map();

  constructor(
    @Optional()
    @Inject('ECC_AUTH_OPTIONS')
    private options: EccAuthModuleOptions = {}
  ) {
    // Set defaults
    this.options = {
      hashIterations: 100000,
      tokenExpiry: 3600,
      cacheSize: 10000,
      cacheTTL: 300,
      ...this.options,
    };

    // Initialize ECC key pair
    this.keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Initialize LRU cache for tokens
    this.tokenCache = new LRU({
      max: this.options.cacheSize,
      ttl: this.options.cacheTTL * 1000,
    });
  }

  private generateUserId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private generateSalt(): Buffer {
    const timestamp = Date.now().toString();
    const randomSalt = crypto.randomBytes(16);
    return Buffer.concat([Buffer.from(timestamp), randomSalt]);
  }

  private async hashPassword(password: string, salt: Buffer): Promise<Buffer> {
    // Argon2 hashing
    const argon2Hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB
      timeCost: Math.max(1, this.options.hashIterations / 1000),
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

  private async verifyPassword(password: string, storedHash: Buffer): Promise<boolean> {
    if (storedHash.length < 48) return false;

    const salt = storedHash.slice(0, 32);
    const expectedHash = storedHash.slice(32);

    try {
      const computedHash = await this.hashPassword(password, salt);
      // Constant-time comparison to prevent timing attacks
      return crypto.timingSafeEqual(computedHash.slice(32), expectedHash);
    } catch (error) {
      return false;
    }
  }

  private createToken(userId: string, username: string): string {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: userId,
      username,
      iat: now,
      exp: now + this.options.tokenExpiry,
    };

    return jwt.sign(payload, this.keyPair.privateKey, { algorithm: 'ES256' });
  }

  private verifyToken(token: string): any {
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
        expires: Date.now() + (this.options.cacheTTL * 1000)
      });

      return payload;
    } catch (error) {
      return null;
    }
  }

  async register(username: string, password: string): Promise<string> {
    if (!username || !password) {
      throw new Error('Username and password are required');
    }

    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    if (this.users.has(username)) {
      throw new Error('User already exists');
    }

    const userId = this.generateUserId();
    const salt = this.generateSalt();
    const passwordHash = await this.hashPassword(password, salt);

    const userData: UserData = {
      id: userId,
      username,
      passwordHash: passwordHash.toString('hex'),
      createdAt: Date.now(),
    };

    this.users.set(username, userData);
    return userId;
  }

  async authenticate(username: string, password: string): Promise<string> {
    const userData = this.users.get(username);
    if (!userData) {
      throw new Error('User not found');
    }

    const storedHash = Buffer.from(userData.passwordHash, 'hex');
    const isValid = await this.verifyPassword(password, storedHash);

    if (!isValid) {
      throw new Error('Invalid password');
    }

    const token = this.createToken(userData.id, username);

    // Cache token
    this.sessions.set(`token:${userData.id}`, {
      sessionId: `token:${userData.id}`,
      userId: userData.id,
      sessionKey: token,
      createdAt: Date.now(),
      expiresAt: Date.now() + (this.options.cacheTTL * 1000)
    });

    return token;
  }

  verifyTokenFromRequest(token: string): UserData {
    const payload = this.verifyToken(token);
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

  async createSession(userId: string): Promise<SessionData> {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const sessionKey = crypto.randomBytes(32);

    const sessionData: SessionData = {
      sessionId,
      userId,
      sessionKey: sessionKey.toString('hex'),
      createdAt: Date.now(),
      expiresAt: Date.now() + (3600 * 1000), // 1 hour
    };

    this.sessions.set(sessionId, sessionData);
    return sessionData;
  }

  getSession(sessionId: string): SessionData | null {
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
}