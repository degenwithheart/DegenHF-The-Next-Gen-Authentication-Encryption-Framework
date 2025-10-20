package com.degenhf.auth

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.slf4j.LoggerFactory
import javax.validation.Valid
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Size

/**
 * REST API controller for ECC-based authentication
 */
@RestController
@RequestMapping("/api/auth")
class AuthController(
    @Autowired private val authHandler: EccAuthHandler
) {
    private val logger = LoggerFactory.getLogger(AuthController::class.java)

    /**
     * Register a new user
     */
    @PostMapping("/register")
    fun register(@Valid @RequestBody request: RegisterRequest): ResponseEntity<RegisterResponse> {
        return try {
            logger.info("Registration request for user: ${request.username}")

            val userId = authHandler.register(request.username, request.password)

            val response = RegisterResponse(
                success = true,
                message = "User registered successfully",
                userId = userId
            )

            logger.info("User registered successfully: ${request.username}")
            ResponseEntity.ok(response)

        } catch (e: Exception) {
            logger.error("Registration failed for user: ${request.username}", e)

            val response = RegisterResponse(
                success = false,
                message = e.message ?: "Registration failed",
                userId = null
            )

            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response)
        }
    }

    /**
     * Authenticate user and return JWT token
     */
    @PostMapping("/authenticate")
    fun authenticate(@Valid @RequestBody request: AuthenticateRequest): ResponseEntity<AuthenticateResponse> {
        return try {
            logger.info("Authentication request for user: ${request.username}")

            val token = authHandler.authenticate(request.username, request.password)

            val response = AuthenticateResponse(
                success = true,
                message = "Authentication successful",
                token = token
            )

            logger.info("User authenticated successfully: ${request.username}")
            ResponseEntity.ok(response)

        } catch (e: Exception) {
            logger.error("Authentication failed for user: ${request.username}", e)

            val response = AuthenticateResponse(
                success = false,
                message = e.message ?: "Authentication failed",
                token = null
            )

            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
        }
    }

    /**
     * Verify JWT token
     */
    @PostMapping("/verify")
    fun verify(@Valid @RequestBody request: VerifyRequest): ResponseEntity<VerifyResponse> {
        return try {
            logger.info("Token verification request")

            val session = authHandler.verifyToken(request.token)

            val response = VerifyResponse(
                success = true,
                message = "Token is valid",
                userId = session.userId,
                username = session.username,
                expiresAt = session.expiresAt
            )

            logger.info("Token verified for user: ${session.username}")
            ResponseEntity.ok(response)

        } catch (e: Exception) {
            logger.error("Token verification failed", e)

            val response = VerifyResponse(
                success = false,
                message = e.message ?: "Token verification failed",
                userId = null,
                username = null,
                expiresAt = null
            )

            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
        }
    }

    /**
     * Get user profile (protected endpoint)
     */
    @GetMapping("/profile")
    fun getProfile(@RequestHeader("Authorization") authHeader: String): ResponseEntity<ProfileResponse> {
        return try {
            // Extract token from Authorization header
            val token = extractTokenFromHeader(authHeader)
            val session = authHandler.verifyToken(token)
            val profile = authHandler.getUserProfile(session.userId)

            val response = ProfileResponse(
                success = true,
                message = "Profile retrieved successfully",
                profile = profile
            )

            logger.info("Profile retrieved for user: ${session.username}")
            ResponseEntity.ok(response)

        } catch (e: Exception) {
            logger.error("Profile retrieval failed", e)

            val response = ProfileResponse(
                success = false,
                message = e.message ?: "Profile retrieval failed",
                profile = null
            )

            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response)
        }
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    fun health(): ResponseEntity<Map<String, String>> {
        return ResponseEntity.ok(mapOf("status" to "healthy", "service" to "ecc-auth"))
    }

    /**
     * Extract JWT token from Authorization header
     */
    private fun extractTokenFromHeader(authHeader: String): String {
        if (!authHeader.startsWith("Bearer ")) {
            throw IllegalArgumentException("Invalid Authorization header format")
        }
        return authHeader.substring(7)
    }
}

/**
 * Request/Response DTOs
 */

// Register request
data class RegisterRequest(
    @field:NotBlank(message = "Username is required")
    @field:Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    val username: String,

    @field:NotBlank(message = "Password is required")
    @field:Size(min = 8, message = "Password must be at least 8 characters")
    val password: String
)

// Register response
data class RegisterResponse(
    val success: Boolean,
    val message: String,
    val userId: String?
)

// Authenticate request
data class AuthenticateRequest(
    @field:NotBlank(message = "Username is required")
    val username: String,

    @field:NotBlank(message = "Password is required")
    val password: String
)

// Authenticate response
data class AuthenticateResponse(
    val success: Boolean,
    val message: String,
    val token: String?
)

// Verify request
data class VerifyRequest(
    @field:NotBlank(message = "Token is required")
    val token: String
)

// Verify response
data class VerifyResponse(
    val success: Boolean,
    val message: String,
    val userId: String?,
    val username: String?,
    val expiresAt: java.time.Instant?
)

// Profile response
data class ProfileResponse(
    val success: Boolean,
    val message: String,
    val profile: UserProfile?
)