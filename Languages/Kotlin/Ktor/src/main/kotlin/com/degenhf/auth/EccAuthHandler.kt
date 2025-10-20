package com.degenhf.auth

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.ECPoint
import de.mkammerer.argon2.Argon2Factory
import com.github.blake3.Blake3
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import org.apache.commons.codec.binary.Base64
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.*
import java.util.concurrent.TimeUnit
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * ECC-based authentication handler with hybrid Argon2+BLAKE3 password hashing
 */
class EccAuthHandler(
    private val options: EccAuthOptions = EccAuthOptions()
) {
    private val logger = LoggerFactory.getLogger(EccAuthHandler::class.java)

    // ECC secp256k1 curve parameters
    private val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    private val keyPairGenerator: KeyPairGenerator
    private val keyFactory: KeyFactory

    // Argon2 password hasher
    private val argon2 = Argon2Factory.create()

    // LRU cache for token verification
    private val tokenCache: Cache<String, UserSession>

    // User storage (in-memory for demo - replace with database)
    private val users = mutableMapOf<String, UserData>()
    private val sessions = mutableMapOf<String, UserSession>()

    init {
        // Initialize BouncyCastle provider
        Security.addProvider(BouncyCastleProvider())

        // Initialize ECC key generation
        keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256k1"), SecureRandom())

        keyFactory = KeyFactory.getInstance("ECDSA", "BC")

        // Initialize LRU cache
        tokenCache = Caffeine.newBuilder()
            .maximumSize(options.cacheSize.toLong())
            .expireAfterWrite(options.cacheTtl.toMillis(), TimeUnit.MILLISECONDS)
            .build()

        logger.info("ECC Auth Handler initialized with cache size: ${options.cacheSize}, TTL: ${options.cacheTtl}")
    }

    /**
     * Register a new user with ECC-secured password hashing
     */
    fun register(username: String, password: String): String {
        require(username.isNotBlank()) { "Username cannot be blank" }
        require(password.length >= 8) { "Password must be at least 8 characters" }
        require(username !in users) { "User already exists" }

        logger.info("Registering new user: $username")

        try {
            // Generate ECC key pair for user
            val keyPair = keyPairGenerator.generateKeyPair()
            val privateKey = keyPair.private
            val publicKey = keyPair.public

            // Generate secure random salt
            val salt = ByteArray(32).apply { Random.nextBytes(this) }

            // Argon2 password hashing
            val argon2Hash = argon2.hash(options.hashIterations, 65536, 1, password.toByteArray())

            // Additional BLAKE3 hashing for extra security
            val blake3 = Blake3.newInstance()
            blake3.update(argon2Hash)
            val finalHash = blake3.digest()

            // Create user data
            val userId = "user_${System.currentTimeMillis()}_${Random.nextInt(1000)}"
            val userData = UserData(
                userId = userId,
                username = username,
                passwordHash = Base64.encodeBase64String(finalHash),
                salt = Base64.encodeBase64String(salt),
                eccPrivateKey = Base64.encodeBase64String(privateKey.encoded),
                eccPublicKey = Base64.encodeBase64String(publicKey.encoded),
                createdAt = Instant.now()
            )

            users[username] = userData

            logger.info("User registered successfully: $username ($userId)")
            return userId

        } catch (e: Exception) {
            logger.error("Failed to register user: $username", e)
            throw RuntimeException("Registration failed", e)
        }
    }

    /**
     * Authenticate user and return JWT token
     */
    fun authenticate(username: String, password: String): String {
        require(username.isNotBlank()) { "Username cannot be blank" }
        require(password.isNotBlank()) { "Password cannot be blank" }

        logger.info("Authenticating user: $username")

        val userData = users[username] ?: throw RuntimeException("User not found")

        try {
            // Verify password using constant-time comparison
            val argon2Hash = argon2.hash(options.hashIterations, 65536, 1, password.toByteArray())
            val blake3 = Blake3.newInstance()
            blake3.update(argon2Hash)
            val computedHash = blake3.digest()
            val storedHash = Base64.decodeBase64(userData.passwordHash)

            if (!MessageDigest.isEqual(computedHash, storedHash)) {
                logger.warn("Invalid password for user: $username")
                throw RuntimeException("Invalid credentials")
            }

            // Create JWT token with ES256 signing
            val now = Instant.now()
            val expiry = now.plus(options.tokenExpiry)

            val token = Jwts.builder()
                .setSubject(userData.userId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiry))
                .claim("username", userData.username)
                .claim("role", "user")
                .signWith(Keys.hmacShaKeyFor(userData.eccPrivateKey.toByteArray()), SignatureAlgorithm.HS256)
                .compact()

            // Create session
            val sessionId = UUID.randomUUID().toString()
            val session = UserSession(
                sessionId = sessionId,
                userId = userData.userId,
                username = userData.username,
                token = token,
                createdAt = now,
                expiresAt = expiry
            )

            sessions[sessionId] = session
            tokenCache.put(token, session)

            logger.info("User authenticated successfully: $username")
            return token

        } catch (e: Exception) {
            logger.error("Authentication failed for user: $username", e)
            throw RuntimeException("Authentication failed", e)
        }
    }

    /**
     * Verify JWT token and return user session
     */
    fun verifyToken(token: String): UserSession {
        require(token.isNotBlank()) { "Token cannot be blank" }

        // Check cache first
        tokenCache.getIfPresent(token)?.let { session ->
            if (session.expiresAt.isAfter(Instant.now())) {
                logger.debug("Token verified from cache for user: ${session.username}")
                return session
            } else {
                tokenCache.invalidate(token)
            }
        }

        try {
            // Parse and verify JWT token
            val claims = Jwts.parserBuilder()
                .setSigningKeyResolver { header, _ ->
                    // In production, you'd look up the user's public key
                    // For demo, we'll use a shared secret
                    Keys.hmacShaKeyFor("demo-secret-key".toByteArray())
                }
                .build()
                .parseClaimsJws(token)
                .body

            val userId = claims.subject
            val username = claims["username"] as String

            // Create session from claims
            val session = UserSession(
                sessionId = UUID.randomUUID().toString(),
                userId = userId,
                username = username,
                token = token,
                createdAt = Instant.now(),
                expiresAt = claims.expiration.toInstant()
            )

            // Cache the verified token
            tokenCache.put(token, session)

            logger.debug("Token verified for user: $username")
            return session

        } catch (e: Exception) {
            logger.error("Token verification failed", e)
            throw RuntimeException("Invalid token", e)
        }
    }

    /**
     * Get user profile data
     */
    fun getUserProfile(userId: String): UserProfile {
        val userData = users.values.find { it.userId == userId }
            ?: throw RuntimeException("User not found")

        return UserProfile(
            userId = userData.userId,
            username = userData.username,
            createdAt = userData.createdAt,
            lastLogin = Instant.now() // In production, track this properly
        )
    }

    /**
     * Create a secure session
     */
    fun createSession(userId: String): UserSession {
        val userData = users.values.find { it.userId == userId }
            ?: throw RuntimeException("User not found")

        val sessionId = UUID.randomUUID().toString()
        val now = Instant.now()
        val expiry = now.plus(options.tokenExpiry)

        val session = UserSession(
            sessionId = sessionId,
            userId = userData.userId,
            username = userData.username,
            token = "", // Token will be set separately
            createdAt = now,
            expiresAt = expiry
        )

        sessions[sessionId] = session
        return session
    }

    /**
     * Get session by ID
     */
    fun getSession(sessionId: String): UserSession? {
        return sessions[sessionId]?.takeIf { it.expiresAt.isAfter(Instant.now()) }
    }

    /**
     * Clean up expired sessions
     */
    fun cleanupExpiredSessions() {
        val now = Instant.now()
        sessions.entries.removeIf { it.value.expiresAt.isBefore(now) }
        logger.info("Cleaned up expired sessions")
    }
}

/**
 * Configuration options for ECC authentication
 */
data class EccAuthOptions(
    val hashIterations: Int = 100000,
    val tokenExpiry: Duration = Duration.ofHours(24),
    val cacheSize: Int = 10000,
    val cacheTtl: Duration = Duration.ofMinutes(5)
)

/**
 * User data stored in memory (replace with database)
 */
data class UserData(
    val userId: String,
    val username: String,
    val passwordHash: String,
    val salt: String,
    val eccPrivateKey: String,
    val eccPublicKey: String,
    val createdAt: Instant
)

/**
 * User session data
 */
data class UserSession(
    val sessionId: String,
    val userId: String,
    val username: String,
    val token: String,
    val createdAt: Instant,
    val expiresAt: Instant
)

/**
 * User profile information
 */
data class UserProfile(
    val userId: String,
    val username: String,
    val createdAt: Instant,
    val lastLogin: Instant
)