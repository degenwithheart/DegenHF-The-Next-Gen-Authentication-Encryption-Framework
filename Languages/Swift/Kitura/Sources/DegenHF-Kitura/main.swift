import Foundation
import Kitura
import KituraCORS
import SwiftyJSON

// ECC-based authentication handler
class EccAuthHandler {
    private var users: [String: UserData] = [:]
    private var sessions: [String: UserSession] = [:]

    // ECC secp256k1 curve parameters (simplified for demo)
    private let curveOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

    struct UserData {
        let userId: String
        let username: String
        let passwordHash: String
        let salt: String
        let eccPrivateKey: String
        let eccPublicKey: String
        let createdAt: Date
    }

    struct UserSession {
        let sessionId: String
        let userId: String
        let username: String
        let token: String
        let createdAt: Date
        let expiresAt: Date
    }

    struct UserProfile {
        let userId: String
        let username: String
        let createdAt: Date
        let lastLogin: Date
    }

    // Register a new user
    func register(username: String, password: String) throws -> String {
        guard username.count >= 3 && username.count <= 50 else {
            throw AuthError.invalidUsername
        }
        guard password.count >= 8 else {
            throw AuthError.weakPassword
        }
        guard users[username] == nil else {
            throw AuthError.userExists
        }

        // Generate ECC key pair (simplified for demo)
        let privateKey = generatePrivateKey()
        let publicKey = derivePublicKey(from: privateKey)

        // Generate secure random salt
        let salt = generateSalt()

        // Argon2 password hashing (simplified implementation)
        let passwordData = password.data(using: .utf8)!
        let saltData = salt.data(using: .utf8)!
        let argon2Hash = try argon2Hash(password: passwordData, salt: saltData)

        // Additional BLAKE3 hashing
        let blake3Hash = try blake3Hash(data: argon2Hash)

        let userId = "user_\(Int(Date().timeIntervalSince1970))_\(Int.random(in: 0...999))"
        let userData = UserData(
            userId: userId,
            username: username,
            passwordHash: blake3Hash.base64EncodedString(),
            salt: salt,
            eccPrivateKey: privateKey,
            eccPublicKey: publicKey,
            createdAt: Date()
        )

        users[username] = userData

        print("User registered successfully: \(username) (\(userId))")
        return userId
    }

    // Authenticate user and return JWT token
    func authenticate(username: String, password: String) throws -> String {
        guard let userData = users[username] else {
            throw AuthError.userNotFound
        }

        // Verify password
        let passwordData = password.data(using: .utf8)!
        let saltData = userData.salt.data(using: .utf8)!
        let computedArgon2Hash = try argon2Hash(password: passwordData, salt: saltData)
        let computedBlake3Hash = try blake3Hash(data: computedArgon2Hash)

        guard let storedHash = Data(base64Encoded: userData.passwordHash),
              constantTimeCompare(computedBlake3Hash, storedHash) else {
            throw AuthError.invalidCredentials
        }

        // Create JWT token
        let now = Date()
        let expiry = now.addingTimeInterval(24 * 60 * 60) // 24 hours

        let payload: [String: Any] = [
            "sub": userData.userId,
            "username": userData.username,
            "iat": Int(now.timeIntervalSince1970),
            "exp": Int(expiry.timeIntervalSince1970)
        ]

        let token = try createJWT(payload: payload, privateKey: userData.eccPrivateKey)

        print("User authenticated successfully: \(username)")
        return token
    }

    // Verify JWT token
    func verifyToken(_ token: String) throws -> UserSession {
        let payload = try verifyJWT(token: token)

        guard let userId = payload["sub"] as? String,
              let username = payload["username"] as? String,
              let exp = payload["exp"] as? Int else {
            throw AuthError.invalidToken
        }

        let expiresAt = Date(timeIntervalSince1970: TimeInterval(exp))
        guard expiresAt > Date() else {
            throw AuthError.tokenExpired
        }

        let session = UserSession(
            sessionId: UUID().uuidString,
            userId: userId,
            username: username,
            token: token,
            createdAt: Date(),
            expiresAt: expiresAt
        )

        return session
    }

    // Get user profile
    func getUserProfile(userId: String) throws -> UserProfile {
        let userData = users.values.first { $0.userId == userId }
        guard let userData = userData else {
            throw AuthError.userNotFound
        }

        return UserProfile(
            userId: userData.userId,
            username: userData.username,
            createdAt: userData.createdAt,
            lastLogin: Date()
        )
    }

    // Helper methods (simplified implementations for demo)
    private func generatePrivateKey() -> String {
        // Generate a random 256-bit private key
        var key = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, key.count, &key)
        return Data(key).base64EncodedString()
    }

    private func derivePublicKey(from privateKey: String) -> String {
        // Simplified public key derivation (in production, use proper ECC math)
        return "public_key_derived_from_\(privateKey.prefix(16))"
    }

    private func generateSalt() -> String {
        var salt = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt)
        return Data(salt).base64EncodedString()
    }

    private func argon2Hash(password: Data, salt: Data) throws -> Data {
        // Simplified Argon2 implementation (use proper crypto library in production)
        let combined = password + salt
        return SHA256.hash(data: combined)
    }

    private func blake3Hash(data: Data) throws -> Data {
        // Simplified BLAKE3 implementation (use proper crypto library in production)
        return SHA256.hash(data: data)
    }

    private func createJWT(payload: [String: Any], privateKey: String) throws -> String {
        // Simplified JWT creation (use proper JWT library in production)
        let header = ["alg": "HS256", "typ": "JWT"]
        let headerData = try JSONSerialization.data(withJSONObject: header)
        let payloadData = try JSONSerialization.data(withJSONObject: payload)

        let headerB64 = headerData.base64EncodedString()
        let payloadB64 = payloadData.base64EncodedString()

        let message = "\(headerB64).\(payloadB64)"
        let signature = SHA256.hash(data: message.data(using: .utf8)!)

        return "\(message).\(signature.base64EncodedString())"
    }

    private func verifyJWT(token: String) throws -> [String: Any] {
        // Simplified JWT verification (use proper JWT library in production)
        let parts = token.split(separator: ".")
        guard parts.count == 3 else {
            throw AuthError.invalidToken
        }

        let payloadB64 = String(parts[1])
        guard let payloadData = Data(base64Encoded: payloadB64),
              let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw AuthError.invalidToken
        }

        return payload
    }

    private func constantTimeCompare(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }
        return result == 0
    }
}

// Authentication errors
enum AuthError: Error {
    case invalidUsername
    case weakPassword
    case userExists
    case userNotFound
    case invalidCredentials
    case invalidToken
    case tokenExpired
}

// API Response structures
struct APIResponse<T: Encodable>: Encodable {
    let success: Bool
    let message: String
    let data: T?
}

struct RegisterRequest: Decodable {
    let username: String
    let password: String
}

struct AuthenticateRequest: Decodable {
    let username: String
    let password: String
}

struct VerifyRequest: Decodable {
    let token: String
}

struct RegisterResponse: Encodable {
    let success: Bool
    let message: String
    let userId: String?
}

struct AuthenticateResponse: Encodable {
    let success: Bool
    let message: String
    let token: String?
}

struct VerifyResponse: Encodable {
    let success: Bool
    let message: String
    let userId: String?
    let username: String?
    let expiresAt: Date?
}

struct ProfileResponse: Encodable {
    let success: Bool
    let message: String
    let profile: UserProfile?
}

// Main application
let authHandler = EccAuthHandler()

// Create Kitura router
let router = Router()

// Enable CORS
let cors = CORS(options: Options(
    allowedOrigin: .all,
    allowedHeaders: ["Content-Type", "Authorization"],
    allowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    maxAge: 3600
))
router.all(middleware: cors)

// Health check endpoint
router.get("/api/auth/health") { request, response, next in
    let healthResponse: [String: String] = [
        "status": "healthy",
        "service": "ecc-auth"
    ]
    response.send(json: JSON(healthResponse))
    next()
}

// Register endpoint
router.post("/api/auth/register") { request, response, next in
    do {
        guard let json = request.body?.asJSON,
              let username = json["username"].string,
              let password = json["password"].string else {
            throw AuthError.invalidToken
        }

        let userId = try authHandler.register(username: username, password: password)
        let apiResponse = RegisterResponse(success: true, message: "User registered successfully", userId: userId)
        response.send(json: JSON(apiResponse))
    } catch let error as AuthError {
        let message: String
        switch error {
        case .invalidUsername:
            message = "Username must be between 3 and 50 characters"
        case .weakPassword:
            message = "Password must be at least 8 characters"
        case .userExists:
            message = "User already exists"
        default:
            message = "Registration failed"
        }
        let apiResponse = RegisterResponse(success: false, message: message, userId: nil)
        response.status(.badRequest).send(json: JSON(apiResponse))
    } catch {
        let apiResponse = RegisterResponse(success: false, message: "Registration failed", userId: nil)
        response.status(.badRequest).send(json: JSON(apiResponse))
    }
    next()
}

// Authenticate endpoint
router.post("/api/auth/authenticate") { request, response, next in
    do {
        guard let json = request.body?.asJSON,
              let username = json["username"].string,
              let password = json["password"].string else {
            throw AuthError.invalidToken
        }

        let token = try authHandler.authenticate(username: username, password: password)
        let apiResponse = AuthenticateResponse(success: true, message: "Authentication successful", token: token)
        response.send(json: JSON(apiResponse))
    } catch let error as AuthError {
        let message: String
        switch error {
        case .userNotFound, .invalidCredentials:
            message = "Invalid credentials"
        default:
            message = "Authentication failed"
        }
        let apiResponse = AuthenticateResponse(success: false, message: message, token: nil)
        response.status(.unauthorized).send(json: JSON(apiResponse))
    } catch {
        let apiResponse = AuthenticateResponse(success: false, message: "Authentication failed", token: nil)
        response.status(.unauthorized).send(json: JSON(apiResponse))
    }
    next()
}

// Verify endpoint
router.post("/api/auth/verify") { request, response, next in
    do {
        guard let json = request.body?.asJSON,
              let token = json["token"].string else {
            throw AuthError.invalidToken
        }

        let session = try authHandler.verifyToken(token)
        let apiResponse = VerifyResponse(
            success: true,
            message: "Token is valid",
            userId: session.userId,
            username: session.username,
            expiresAt: session.expiresAt
        )
        response.send(json: JSON(apiResponse))
    } catch let error as AuthError {
        let message: String
        switch error {
        case .invalidToken, .tokenExpired:
            message = "Invalid token"
        default:
            message = "Token verification failed"
        }
        let apiResponse = VerifyResponse(success: false, message: message, userId: nil, username: nil, expiresAt: nil)
        response.status(.unauthorized).send(json: JSON(apiResponse))
    } catch {
        let apiResponse = VerifyResponse(success: false, message: message, userId: nil, username: nil, expiresAt: nil)
        response.status(.unauthorized).send(json: JSON(apiResponse))
    }
    next()
}

// Profile endpoint
router.get("/api/auth/profile") { request, response, next in
    do {
        guard let authHeader = request.headers["Authorization"],
              authHeader.hasPrefix("Bearer "),
              authHeader.count > 7 else {
            throw AuthError.invalidToken
        }

        let token = String(authHeader.dropFirst(7))
        let session = try authHandler.verifyToken(token)
        let profile = try authHandler.getUserProfile(userId: session.userId)

        let apiResponse = ProfileResponse(success: true, message: "Profile retrieved successfully", profile: profile)
        response.send(json: JSON(apiResponse))
    } catch let error as AuthError {
        let message: String
        switch error {
        case .invalidToken, .tokenExpired:
            message = "Invalid token"
        case .userNotFound:
            message = "User not found"
        default:
            message = "Profile retrieval failed"
        }
        let apiResponse = ProfileResponse(success: false, message: message, profile: nil)
        response.status(.unauthorized).send(json: JSON(apiResponse))
    } catch {
        let apiResponse = ProfileResponse(success: false, message: "Profile retrieval failed", profile: nil)
        response.status(.unauthorized).send(json: JSON(apiResponse))
    }
    next()
}

// Root endpoint
router.get("/") { request, response, next in
    let info: [String: Any] = [
        "message": "DegenHF ECC Authentication API - Swift Kitura",
        "version": "1.0.0",
        "endpoints": "/api/auth/*"
    ]
    response.send(json: JSON(info))
    next()
}

// Start the server
Kitura.addHTTPServer(onPort: 8080, with: router)
Kitura.run()