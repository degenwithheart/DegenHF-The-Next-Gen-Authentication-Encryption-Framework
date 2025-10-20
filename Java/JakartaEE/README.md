# DegenHF Jakarta EE ECC Authentication

Enhanced Jakarta EE authentication module with ECC-based security, optimized for enterprise applications.

## Features

- **ECC secp256k1** cryptography with constant-time operations
- **Argon2 + BLAKE3** password hashing for maximum security
- **JWT tokens** with ES256 signing
- **CDI integration** for dependency injection
- **JAX-RS** resource integration
- **Thread-safe** concurrent operations
- **Configurable** security parameters

## Installation

Since this package is currently only available from the GitHub repository, add JitPack repository and dependency to your `pom.xml`:

```xml
<reositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.degenwithheart.DegenHF</groupId>
    <artifactId>degenhf-ecc-auth-jakarta</artifactId>
    <version>main-SNAPSHOT</version>
</dependency>
```

## Configuration

Create `microprofile-config.properties`:

```properties
degenhf.ecc.auth.hashIterations=100000
degenhf.ecc.auth.tokenExpiry=3600
degenhf.ecc.auth.cacheSize=10000
degenhf.ecc.auth.cacheTtl=300
```

## Usage

```java
@ApplicationScoped
public class AuthResource {

    @Inject
    private EccAuthService authService;

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(RegisterRequest request) {
        try {
            String userId = authService.register(request.getUsername(), request.getPassword());
            return Response.ok(Map.of("userId", userId)).build();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(LoginRequest request) {
        try {
            String token = authService.authenticate(request.getUsername(), request.getPassword());
            return Response.ok(Map.of("token", token)).build();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/profile")
    @JWTAuth
    @Produces(MediaType.APPLICATION_JSON)
    public Response getProfile(@Context SecurityContext context) {
        // User info available through security context
        return Response.ok(context.getUserPrincipal()).build();
    }
}
```

## CDI Integration

```java
@ApplicationScoped
public class AuthService {

    @Inject
    private EccAuthService eccAuthService;

    public void someBusinessLogic() {
        // Use ECC auth service
        eccAuthService.register("user", "password");
    }
}
```

## Security Features

- **Constant-time operations** prevent timing attacks
- **ECC key pairs** generated per application
- **Secure random** salts and session keys
- **Token caching** with automatic expiration
- **Thread-safe** concurrent operations

## Dependencies

- Jakarta EE 9+
- MicroProfile Config
- Bouncy Castle (ECC support)
- Argon2-JVM
- Caffeine Cache
- JJWT</content>
<parameter name="filePath">/Users/degenwithheart/GitHub/DegenHF/Packages/Java/JakartaEE/README.md