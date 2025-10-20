# DegenHF NestJS ECC Authentication Package

Enhanced NestJS authentication module with ECC-based security, optimized for speed and security.

## Features

- **ECC Authentication**: secp256k1/Curve25519 cryptography with optimized operations
- **Enhanced Security**: Argon2+BLAKE3 password hashing with configurable iterations
- **Token Management**: ECC-signed JWT tokens with LRU caching and TTL
- **Session Security**: ECDH+AES-GCM session encryption
- **Performance Optimizations**:
  - LRU caching with configurable size and TTL (5-minute default)
  - Constant-time operations to prevent timing attacks
  - Reduced memory allocations
  - Dependency injection support
- **Security Enhancements**:
  - Enhanced salt generation
  - Timing attack protection
  - Additional input validations
  - Configurable security parameters

## Installation

```bash
npm install degenhf-nestjs-ecc-auth
```

## Usage

### Module Setup

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { EccAuthModule } from 'degenhf-nestjs-ecc-auth';

@Module({
  imports: [
    EccAuthModule.forRoot({
      hashIterations: 100000,
      tokenExpiry: 3600,    // 1 hour
      cacheSize: 10000,
      cacheTTL: 300         // 5 minutes
    }),
  ],
})
export class AppModule {}
```

### Service Usage

```typescript
// auth.service.ts
import { Injectable } from '@nestjs/common';
import { EccAuthService } from 'degenhf-nestjs-ecc-auth';

@Injectable()
export class AuthService {
  constructor(private readonly eccAuthService: EccAuthService) {}

  async register(username: string, password: string) {
    return this.eccAuthService.register(username, password);
  }

  async login(username: string, password: string) {
    return this.eccAuthService.authenticate(username, password);
  }
}
```

### Controller Implementation

```typescript
// auth.controller.ts
import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { EccAuthGuard } from 'degenhf-nestjs-ecc-auth';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() body: { username: string; password: string }) {
    const userId = await this.authService.register(body.username, body.password);
    return { userId, status: 'success' };
  }

  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    const token = await this.authService.login(body.username, body.password);
    return { token, status: 'success' };
  }

  @Post('profile')
  @UseGuards(EccAuthGuard)
  getProfile(@Req() req) {
    return {
      user: req.user,
      message: 'Profile accessed successfully'
    };
  }
}
```

### Guard Usage

```typescript
// protected.controller.ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { EccAuthGuard } from 'degenhf-nestjs-ecc-auth';

@Controller('protected')
@UseGuards(EccAuthGuard)
export class ProtectedController {
  @Get('data')
  getProtectedData(@Req() req) {
    return {
      data: 'This is protected data',
      user: req.user
    };
  }
}
```

## Configuration

The module accepts the following configuration options:

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

This package is optimized for high-performance NestJS applications:

- **Dependency Injection**: Full DI support with providers and guards
- **Caching**: LRU cache for tokens reduces verification overhead
- **Async Operations**: Native async/await support
- **Memory Efficiency**: Minimal allocations and efficient data structures

## Dependencies

- @nestjs/common >= 8.0
- @nestjs/core >= 8.0
- @nestjs/platform-express >= 8.0
- argon2
- blake3
- jsonwebtoken
- lru-cache
- rxjs

## License

MIT