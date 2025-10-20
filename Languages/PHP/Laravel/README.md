# DegenHF Laravel ECC Authentication

Enhanced Laravel authentication package with ECC-based security, optimized for speed and performance.

## Features

- **ECC secp256k1** cryptography with constant-time operations
- **Argon2 + BLAKE3** password hashing for maximum security
- **JWT tokens** with ES256 signing
- **Laravel integration** with service providers and facades
- **Cache integration** (Redis/file cache support)
- **Thread-safe** async operations
- **Configurable** security parameters

## Installation

Add to your `composer.json`:

```json
{
    "require": {
        "degenhf/ecc-auth-laravel": "^1.0"
    }
}
```

Run composer install:

```bash
composer install
```

Publish the configuration:

```bash
php artisan vendor:publish --provider="DegenHF\EccAuth\EccAuthServiceProvider"
```

## Configuration

Edit `config/ecc-auth.php`:

```php
return [
    'hash_iterations' => env('ECC_AUTH_HASH_ITERATIONS', 100000),
    'token_expiry' => env('ECC_AUTH_TOKEN_EXPIRY', 3600),
    'cache_size' => env('ECC_AUTH_CACHE_SIZE', 10000),
    'cache_ttl' => env('ECC_AUTH_CACHE_TTL', 300),
];
```

## Usage

### Basic Usage

```php
use DegenHF\EccAuth\Facades\EccAuth;

// Register a user
$userId = EccAuth::register('username', 'password123');

// Authenticate
$token = EccAuth::authenticate('username', 'password123');

// Verify token
$user = EccAuth::verifyToken($token);
```

### Middleware

```php
// In routes/web.php or routes/api.php
Route::middleware('ecc.auth')->group(function () {
    Route::get('/profile', function () {
        return auth()->user();
    });
});
```

### Controller Example

```php
<?php

namespace App\Http\Controllers;

use DegenHF\EccAuth\Facades\EccAuth;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        try {
            $userId = EccAuth::register(
                $request->input('username'),
                $request->input('password')
            );

            return response()->json(['userId' => $userId]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        }
    }

    public function login(Request $request): JsonResponse
    {
        try {
            $token = EccAuth::authenticate(
                $request->input('username'),
                $request->input('password')
            );

            return response()->json(['token' => $token]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }

    public function profile(Request $request): JsonResponse
    {
        return response()->json(['user' => $request->user()]);
    }
}
```

## Security Features

- **Constant-time operations** prevent timing attacks
- **ECC key pairs** generated per application
- **Secure random** salts and session keys
- **Token caching** with automatic expiration
- **Thread-safe** concurrent operations

## Performance Optimizations

- Laravel cache integration
- Configurable hash iterations
- Async password hashing
- Minimal memory allocations

## Dependencies

- Laravel 9+
- PHP 8.1+
- OpenSSL extension
- Sodium extension (for Argon2)
- Redis (recommended for caching)</content>
<parameter name="filePath">/Users/degenwithheart/GitHub/DegenHF/Packages/PHP/Laravel/README.md