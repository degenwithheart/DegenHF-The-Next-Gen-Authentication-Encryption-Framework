# DegenHF Spring Boot ECC Authentication

Enhanced Spring Boot authentication module with ECC-based security, optimized for speed and performance.

## Features

- **ECC secp256k1** cryptography with constant-time operations
- **Argon2 + BLAKE3** password hashing for maximum security
- **JWT tokens** with ES256 signing
- **LRU caching** (5-minute TTL) for performance
- **Thread-safe** async operations
- **Configurable** iterations and timeouts
- **Spring Security** integration

## Installation

Since this package is currently only available from the GitHub repository, add JitPack repository and dependency to your `pom.xml`:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.degenwithheart.DegenHF</groupId>
    <artifactId>degenhf-ecc-auth-spring-boot</artifactId>
    <version>main-SNAPSHOT</version>
</dependency>
```

## Configuration

Add to `application.yml`:

```yaml
degenhf:
  ecc:
    auth:
      hashIterations: 100000
      tokenExpiry: 3600
      cacheSize: 10000
      cacheTtl: 300
```

## Usage

```java
@SpringBootApplication
@EnableEccAuth
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private EccAuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            String userId = authService.register(request.getUsername(), request.getPassword());
            return ResponseEntity.ok(Map.of("userId", userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            String token = authService.authenticate(request.getUsername(), request.getPassword());
            return ResponseEntity.ok(Map.of("token", token));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getProfile(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(user);
    }
}
```

## Security Features

- **Constant-time operations** prevent timing attacks
- **ECC key pairs** generated per instance
- **Secure random** salts and session keys
- **Token caching** with automatic expiration
- **Thread-safe** concurrent operations

## Performance Optimizations

- LRU cache for token verification
- Configurable hash iterations
- Async password hashing
- Minimal memory allocations

## Dependencies

- Spring Boot 3.0+
- Spring Security 6.0+
- Bouncy Castle (ECC support)
- Argon2-JVM
- Caffeine Cache</content>
<parameter name="filePath">/Users/degenwithheart/GitHub/DegenHF/Packages/Java/SpringBoot/README.md