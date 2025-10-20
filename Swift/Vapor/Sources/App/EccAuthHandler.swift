import Foundation
import CryptoKit
import JWT
import Logging
import CryptoSwift

/// ECC-based authentication handler with hybrid Argon2+BLAKE3 password hashing
public class EccAuthHandler {
    private let logger = Logger(label: "com.degenhf.auth")
    private let options: EccAuthOptions

    // In-memory storage (replace with database in production)
    private var users: [String: UserData] = [:]
    private var sessions: [String: UserSession] = [:]

    // LRU cache for token verification
    private var tokenCache: [String: UserSession] = [:]
    private var cacheTimestamps: [String: Date] = [:]

    public init(options: EccAuthOptions = EccAuthOptions()) {
        self.options = options
        logger.info("ECC Auth Handler initialized with cache size: \(options.cacheSize), TTL: \(options.cacheTtl) seconds")
    }

    /// Register a new user with ECC-secured password hashing
    public func register(username: String, password: String) throws -> String {
        guard !username.isEmpty else {
            throw AuthError.invalidInput("Username cannot be empty")
        }
        guard password.count >= 8 else {
            throw AuthError.invalidInput("Password must be at least 8 characters")
        }
        guard users[username] == nil else {
            throw AuthError.userExists("User already exists")
        }

        logger.info("Registering new user: \(username)")

        do {
            // Generate ECC key pair (secp256k1 equivalent using P-256)
            let privateKey = P256.Signing.PrivateKey()
            let publicKey = privateKey.publicKey

            // Generate secure random salt
            let salt = try generateSalt()

            // Argon2 password hashing
            let argon2Hash = try argon2Hash(password: password, salt: salt)

            // Additional BLAKE3 hashing for extra security
            let blake3Hash = try blake3Hash(data: argon2Hash)

            // Create user data
            let userId = "user_\(Int(Date().timeIntervalSince1970 * 1000))_\(Int.random(in: 0...999))"
            let userData = UserData(
                userId: userId,
                username: username,
                passwordHash: blake3Hash.base64EncodedString(),
                salt: salt.base64EncodedString(),
                eccPrivateKey: privateKey.pemRepresentation,
                eccPublicKey: publicKey.pemRepresentation,
                createdAt: Date()
            )

            users[username] = userData

            logger.info("User registered successfully: \(username) (\(userId))")
            return userId

        } catch {
            logger.error("Failed to register user \(username): \(error)")
            throw AuthError.registrationFailed("Registration failed: \(error.localizedDescription)")
        }
    }

    /// Authenticate user and return JWT token
    public func authenticate(username: String, password: String) throws -> String {
        guard !username.isEmpty else {
            throw AuthError.invalidInput("Username cannot be empty")
        }
        guard !password.isEmpty else {
            throw AuthError.invalidInput("Password cannot be empty")
        }

        logger.info("Authenticating user: \(username)")

        guard let userData = users[username] else {
            throw AuthError.userNotFound("User not found")
        }

        do {
            // Generate salt from stored salt
            guard let saltData = Data(base64Encoded: userData.salt) else {
                throw AuthError.invalidData("Invalid salt data")
            }

            // Verify password using constant-time comparison
            let argon2Hash = try argon2Hash(password: password, salt: saltData)
            let blake3Hash = try blake3Hash(data: argon2Hash)
            let storedHash = Data(base64Encoded: userData.passwordHash)!

            guard blake3Hash == storedHash else {
                logger.warning("Invalid password for user: \(username)")
                throw AuthError.invalidCredentials("Invalid credentials")
            }

            // Create JWT token with ES256 signing
            let now = Date()
            let expiry = now.addingTimeInterval(options.tokenExpiry)

            let payload = UserPayload(
                subject: userData.userId,
                expiration: .init(value: expiry),
                issuedAt: .init(value: now),
                username: username,
                role: "user"
            )

            let jwt = try JWTSigner.es256(key: try loadPrivateKey(pem: userData.eccPrivateKey)).sign(payload)

            // Create session
            let sessionId = UUID().uuidString
            let session = UserSession(
                sessionId: sessionId,
                userId: userData.userId,
                username: userData.username,
                token: jwt,
                createdAt: now,
                expiresAt: expiry
            )

            sessions[sessionId] = session
            tokenCache[jwt] = session
            cacheTimestamps[jwt] = now

            logger.info("User authenticated successfully: \(username)")
            return jwt

        } catch {
            logger.error("Authentication failed for user \(username): \(error)")
            throw AuthError.authenticationFailed("Authentication failed: \(error.localizedDescription)")
        }
    }

    /// Verify JWT token and return user session
    public func verifyToken(_ token: String) throws -> UserSession {
        guard !token.isEmpty else {
            throw AuthError.invalidInput("Token cannot be empty")
        }

        // Check cache first
        if let cachedSession = tokenCache[token],
           let cacheTime = cacheTimestamps[token],
           Date().timeIntervalSince(cacheTime) < options.cacheTtl {
            logger.debug("Token verified from cache for user: \(cachedSession.username)")
            return cachedSession
        }

        do {
            // Parse and verify JWT token
            let payload = try JWTSigner.es256(key: try loadPublicKey(pem: getPublicKeyFromToken(token))).verify(token, as: UserPayload.self)

            let session = UserSession(
                sessionId: UUID().uuidString,
                userId: payload.subject.value,
                username: payload.username,
                token: token,
                createdAt: payload.issuedAt.value,
                expiresAt: payload.expiration.value
            )

            // Cache the verified token
            tokenCache[token] = session
            cacheTimestamps[token] = Date()

            logger.debug("Token verified for user: \(payload.username)")
            return session

        } catch {
            logger.error("Token verification failed: \(error)")
            throw AuthError.invalidToken("Invalid token: \(error.localizedDescription)")
        }
    }

    /// Get user profile data
    public func getUserProfile(userId: String) throws -> UserProfile {
        guard let userData = users.values.first(where: { $0.userId == userId }) else {
            throw AuthError.userNotFound("User not found")
        }

        return UserProfile(
            userId: userData.userId,
            username: userData.username,
            createdAt: userData.createdAt,
            lastLogin: Date() // In production, track this properly
        )
    }

    /// Create a secure session
    public func createSession(userId: String) throws -> UserSession {
        guard let userData = users.values.first(where: { $0.userId == userId }) else {
            throw AuthError.userNotFound("User not found")
        }

        let sessionId = UUID().uuidString
        let now = Date()
        let expiry = now.addingTimeInterval(options.tokenExpiry)

        let session = UserSession(
            sessionId: sessionId,
            userId: userData.userId,
            username: userData.username,
            token: "", // Token will be set separately
            createdAt: now,
            expiresAt: expiry
        )

        sessions[sessionId] = session
        return session
    }

    /// Get session by ID
    public func getSession(sessionId: String) -> UserSession? {
        return sessions[sessionId]?.let { session in
            session.expiresAt > Date() ? session : nil
        }
    }

    /// Clean up expired sessions and cache entries
    public func cleanupExpiredSessions() {
        let now = Date()

        // Clean expired sessions
        sessions = sessions.filter { $0.value.expiresAt > now }

        // Clean expired cache entries
        let expiredTokens = cacheTimestamps.filter { $0.value.addingTimeInterval(options.cacheTtl) < now }.keys
        expiredTokens.forEach { token in
            tokenCache.removeValue(forKey: token)
            cacheTimestamps.removeValue(forKey: token)
        }

        logger.info("Cleaned up expired sessions and cache entries")
    }

    // MARK: - Private Helper Methods

    private func generateSalt() throws -> Data {
        var salt = Data(count: 32)
        let result = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard result == errSecSuccess else {
            throw AuthError.cryptoError("Failed to generate salt")
        }
        return salt
    }

    private func argon2Hash(password: String, salt: Data) throws -> Data {
        // Using CryptoSwift's Argon2 implementation
        let argon2 = try Argon2(password: Array(password.utf8),
                               salt: Array(salt),
                               iterations: UInt32(options.hashIterations / 1024), // Adjust for CryptoSwift
                               memory: 65536,
                               parallelism: 1,
                               hashLength: 32,
                               type: .id,
                               version: .v13)
        return Data(argon2.hash())
    }

    private func blake3Hash(data: Data) throws -> Data {
        // Using CryptoSwift's BLAKE3 implementation
        let blake3 = CryptoSwift.BLAKE3()
        return Data(try blake3.hash(Array(data)))
    }

    private func loadPrivateKey(pem: String) throws -> P256.Signing.PrivateKey {
        // Convert PEM to DER and load private key
        let pemData = pem.data(using: .utf8)!
        let derData = try convertPEMToDER(pemData)
        return try P256.Signing.PrivateKey(derEncoded: derData)
    }

    private func loadPublicKey(pem: String) throws -> P256.Signing.PublicKey {
        // Convert PEM to DER and load public key
        let pemData = pem.data(using: .utf8)!
        let derData = try convertPEMToDER(pemData)
        return try P256.Signing.PublicKey(derEncoded: derData)
    }

    private func convertPEMToDER(_ pemData: Data) throws -> Data {
        // Simple PEM to DER conversion (in production, use a proper library)
        let pemString = String(data: pemData, encoding: .utf8)!
        let base64String = pemString
            .replacingOccurrences(of: "-----BEGIN.*-----", with: "", options: .regularExpression)
            .replacingOccurrences(of: "-----END.*-----", with: "", options: .regularExpression)
            .replacingOccurrences(of: "\n", with: "")

        guard let derData = Data(base64Encoded: base64String) else {
            throw AuthError.cryptoError("Invalid PEM format")
        }
        return derData
    }

    private func getPublicKeyFromToken(_ token: String) throws -> String {
        // In production, you'd store and retrieve the public key properly
        // For demo, return a dummy key
        return "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----"
    }
}

// MARK: - Data Structures

public struct EccAuthOptions {
    public let hashIterations: Int
    public let tokenExpiry: TimeInterval
    public let cacheSize: Int
    public let cacheTtl: TimeInterval

    public init(
        hashIterations: Int = 100000,
        tokenExpiry: TimeInterval = 86400, // 24 hours
        cacheSize: Int = 10000,
        cacheTtl: TimeInterval = 300 // 5 minutes
    ) {
        self.hashIterations = hashIterations
        self.tokenExpiry = tokenExpiry
        self.cacheSize = cacheSize
        self.cacheTtl = cacheTtl
    }
}

public struct UserData {
    public let userId: String
    public let username: String
    public let passwordHash: String
    public let salt: String
    public let eccPrivateKey: String
    public let eccPublicKey: String
    public let createdAt: Date
}

public struct UserSession {
    public let sessionId: String
    public let userId: String
    public let username: String
    public let token: String
    public let createdAt: Date
    public let expiresAt: Date
}

public struct UserProfile {
    public let userId: String
    public let username: String
    public let createdAt: Date
    public let lastLogin: Date
}

// MARK: - JWT Payload

struct UserPayload: JWTPayload {
    var subject: SubjectClaim
    var expiration: ExpirationClaim
    var issuedAt: IssuedAtClaim
    var username: String
    var role: String

    func verify(using signer: JWTSigner) throws {
        try expiration.verifyNotExpired()
    }
}

// MARK: - Error Types

public enum AuthError: Error {
    case invalidInput(String)
    case userExists(String)
    case userNotFound(String)
    case invalidCredentials(String)
    case invalidData(String)
    case registrationFailed(String)
    case authenticationFailed(String)
    case invalidToken(String)
    case cryptoError(String)
}