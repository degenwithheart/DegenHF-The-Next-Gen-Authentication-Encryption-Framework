import Vapor
import JWT

// MARK: - Main Application

@main
struct App {
    static func main() async throws {
        let app = try await Application.make()

        // Configure application
        try configure(app)

        // Run application
        try await app.execute()
    }
}

// MARK: - Configuration

func configure(_ app: Application) async throws {
    // Logging
    app.logger.logLevel = .info

    // JWT Configuration
    await configureJWT(app)

    // Middleware
    app.middleware.use(CORSMiddleware(configuration: .default()))
    app.middleware.use(app.sessions.middleware)

    // Routes
    try routes(app)

    // Initialize auth handler
    let authOptions = EccAuthOptions(
        hashIterations: 100000,
        tokenExpiry: 86400, // 24 hours
        cacheSize: 10000,
        cacheTtl: 300 // 5 minutes
    )

    let authHandler = EccAuthHandler(options: authOptions)
    app.storage.set(EccAuthHandlerKey.self, to: authHandler)

    app.logger.info("DegenHF Vapor server configured and ready")
}

// MARK: - JWT Configuration

func configureJWT(_ app: Application) async {
    // In production, load from secure key management
    let privateKey = P256.Signing.PrivateKey()

    await JWTSignersStorage.configure(app, signers: [
        .es256(key: privateKey)
    ], kid: "degenhf-vapor")
}

// MARK: - Routes

func routes(_ app: Application) throws {
    let authHandler = app.storage.get(EccAuthHandlerKey.self)!

    // Health check
    app.get("health") { req async -> Response in
        let response = Response(status: .ok)
        try response.content.encode([
            "status": "healthy",
            "service": "degenhf-vapor",
            "timestamp": Int(Date().timeIntervalSince1970)
        ])
        return response
    }

    // Public auth routes
    let authRoutes = app.grouped("api", "auth")

    // Register endpoint
    authRoutes.post("register") { req async throws -> Response in
        let registerRequest = try req.content.decode(RegisterRequest.self)

        guard !registerRequest.username.isEmpty else {
            throw Abort(.badRequest, reason: "Username cannot be empty")
        }
        guard registerRequest.password.count >= 8 else {
            throw Abort(.badRequest, reason: "Password must be at least 8 characters")
        }

        do {
            let userId = try authHandler.register(username: registerRequest.username, password: registerRequest.password)
            let response = Response(status: .created)
            try response.content.encode([
                "user_id": userId,
                "message": "User registered successfully"
            ])
            req.logger.info("User registered: \(registerRequest.username)")
            return response
        } catch let error as AuthError {
            req.logger.error("Registration failed: \(error)")
            throw Abort(.badRequest, reason: error.localizedDescription)
        }
    }

    // Login endpoint
    authRoutes.post("login") { req async throws -> Response in
        let loginRequest = try req.content.decode(LoginRequest.self)

        guard !loginRequest.username.isEmpty else {
            throw Abort(.badRequest, reason: "Username cannot be empty")
        }
        guard !loginRequest.password.isEmpty else {
            throw Abort(.badRequest, reason: "Password cannot be empty")
        }

        do {
            let token = try authHandler.authenticate(username: loginRequest.username, password: loginRequest.password)
            let response = Response(status: .ok)
            try response.content.encode([
                "token": token,
                "message": "Login successful"
            ])
            req.logger.info("User logged in: \(loginRequest.username)")
            return response
        } catch let error as AuthError {
            req.logger.error("Login failed: \(error)")
            throw Abort(.unauthorized, reason: error.localizedDescription)
        }
    }

    // Protected routes (require JWT authentication)
    let protectedRoutes = authRoutes.grouped(JWTMiddleware())

    // Verify token endpoint
    protectedRoutes.get("verify") { req async throws -> Response in
        let payload = try req.jwt.verify(as: UserPayload.self)

        let response = Response(status: .ok)
        try response.content.encode([
            "user_id": payload.subject.value,
            "username": payload.username,
            "message": "Token is valid"
        ])
        req.logger.debug("Token verified for user: \(payload.username)")
        return response
    }

    // Get user profile
    protectedRoutes.get("profile") { req async throws -> Response in
        let payload = try req.jwt.verify(as: UserPayload.self)
        let authHandler = req.application.storage.get(EccAuthHandlerKey.self)!

        do {
            let profile = try authHandler.getUserProfile(userId: payload.subject.value)
            let response = Response(status: .ok)
            try response.content.encode([
                "user_id": profile.userId,
                "username": profile.username,
                "profile": [
                    "created_at": ISO8601DateFormatter().string(from: profile.createdAt),
                    "last_login": ISO8601DateFormatter().string(from: profile.lastLogin)
                ]
            ])
            req.logger.debug("Profile retrieved for user: \(profile.username)")
            return response
        } catch let error as AuthError {
            req.logger.error("Profile retrieval failed: \(error)")
            throw Abort(.internalServerError, reason: error.localizedDescription)
        }
    }

    // Example protected route
    app.get("api", "protected") { req async throws -> Response in
        let payload = try req.jwt.verify(as: UserPayload.self)

        let response = Response(status: .ok)
        try response.content.encode([
            "message": "Welcome to protected route, \(payload.username)!",
            "user_id": payload.subject.value,
            "timestamp": Int(Date().timeIntervalSince1970)
        ])
        req.logger.debug("Protected route accessed by: \(payload.username)")
        return response
    }
}

// MARK: - JWT Middleware

struct JWTMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard let token = request.headers.bearerAuthorization?.token else {
            throw Abort(.unauthorized, reason: "Missing or invalid authorization header")
        }

        do {
            let payload = try request.jwt.verify(token, as: UserPayload.self)
            request.storage.set(UserPayload.self, to: payload)
            return try await next.respond(to: request)
        } catch {
            request.logger.error("JWT verification failed: \(error)")
            throw Abort(.unauthorized, reason: "Invalid token")
        }
    }
}

// MARK: - Storage Keys

struct EccAuthHandlerKey: StorageKey {
    typealias Value = EccAuthHandler
}

// MARK: - Request/Response Models

struct RegisterRequest: Content {
    let username: String
    let password: String
}

struct LoginRequest: Content {
    let username: String
    let password: String
}

// MARK: - JWT Payload Extension

extension Request {
    var jwt: JWTSigners {
        application.jwt.signers
    }
}