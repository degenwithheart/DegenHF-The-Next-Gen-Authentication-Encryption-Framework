package com.degenhf.auth

import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import java.time.Duration

/**
 * Main Ktor application for ECC-based authentication
 */
fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {
        module()
    }.start(wait = true)
}

fun Application.module() {
    val logger = LoggerFactory.getLogger("Application")

    // Install content negotiation
    install(ContentNegotiation) {
        jackson()
    }

    // Install CORS
    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        anyHost()
    }

    // Configure JWT authentication
    install(Authentication) {
        jwt("auth-jwt") {
            verifier(JwtConfig.verifier)
            validate { credential ->
                if (credential.payload.getClaim("username").asString() != null) {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }
        }
    }

    // Initialize ECC auth handler
    val authOptions = EccAuthOptions(
        hashIterations = 100000,
        tokenExpiry = Duration.ofHours(24),
        cacheSize = 10000,
        cacheTtl = Duration.ofMinutes(5)
    )

    val authHandler = EccAuthHandler(authOptions)

    // Configure routing
    routing {
        // Health check
        get("/health") {
            call.respond(mapOf("status" to "healthy", "service" to "degenhf-ktor"))
        }

        // Public auth routes
        route("/api/auth") {
            // Register endpoint
            post("/register") {
                try {
                    val request = call.receive<RegisterRequest>()

                    if (request.username.isBlank() || request.password.length < 8) {
                        call.respond(HttpStatusCode.BadRequest, mapOf(
                            "error" to "Invalid input",
                            "message" to "Username must not be blank and password must be at least 8 characters"
                        ))
                        return@post
                    }

                    val userId = authHandler.register(request.username, request.password)
                    call.respond(HttpStatusCode.Created, mapOf(
                        "user_id" to userId,
                        "message" to "User registered successfully"
                    ))

                    logger.info("User registered: ${request.username}")

                } catch (e: Exception) {
                    logger.error("Registration failed", e)
                    call.respond(HttpStatusCode.BadRequest, mapOf(
                        "error" to "Registration failed",
                        "message" to e.message
                    ))
                }
            }

            // Login endpoint
            post("/login") {
                try {
                    val request = call.receive<LoginRequest>()

                    if (request.username.isBlank() || request.password.isBlank()) {
                        call.respond(HttpStatusCode.BadRequest, mapOf(
                            "error" to "Invalid input",
                            "message" to "Username and password are required"
                        ))
                        return@post
                    }

                    val token = authHandler.authenticate(request.username, request.password)
                    call.respond(HttpStatusCode.OK, mapOf(
                        "token" to token,
                        "message" to "Login successful"
                    ))

                    logger.info("User logged in: ${request.username}")

                } catch (e: Exception) {
                    logger.error("Login failed", e)
                    call.respond(HttpStatusCode.Unauthorized, mapOf(
                        "error" to "Authentication failed",
                        "message" to e.message
                    ))
                }
            }
        }

        // Protected routes
        authenticate("auth-jwt") {
            route("/api/auth") {
                // Verify token endpoint
                get("/verify") {
                    try {
                        val principal = call.principal<JWTPrincipal>()!!
                        val username = principal.payload.getClaim("username").asString()

                        call.respond(HttpStatusCode.OK, mapOf(
                            "user_id" to principal.payload.subject,
                            "username" to username,
                            "message" to "Token is valid"
                        ))

                        logger.debug("Token verified for user: $username")

                    } catch (e: Exception) {
                        logger.error("Token verification failed", e)
                        call.respond(HttpStatusCode.Unauthorized, mapOf(
                            "error" to "Token verification failed",
                            "message" to e.message
                        ))
                    }
                }

                // Get user profile
                get("/profile") {
                    try {
                        val principal = call.principal<JWTPrincipal>()!!
                        val userId = principal.payload.subject

                        val profile = authHandler.getUserProfile(userId)
                        call.respond(HttpStatusCode.OK, mapOf(
                            "user_id" to profile.userId,
                            "username" to profile.username,
                            "profile" to mapOf(
                                "created_at" to profile.createdAt.toString(),
                                "last_login" to profile.lastLogin.toString()
                            )
                        ))

                        logger.debug("Profile retrieved for user: ${profile.username}")

                    } catch (e: Exception) {
                        logger.error("Profile retrieval failed", e)
                        call.respond(HttpStatusCode.InternalServerError, mapOf(
                            "error" to "Profile retrieval failed",
                            "message" to e.message
                        ))
                    }
                }
            }

            // Example protected route
            get("/api/protected") {
                val principal = call.principal<JWTPrincipal>()!!
                val username = principal.payload.getClaim("username").asString()

                call.respond(HttpStatusCode.OK, mapOf(
                    "message" to "Welcome to protected route, $username!",
                    "user_id" to principal.payload.subject,
                    "timestamp" to System.currentTimeMillis()
                ))

                logger.debug("Protected route accessed by: $username")
            }
        }
    }

    logger.info("DegenHF Ktor server started on port 8080")
}

/**
 * JWT Configuration
 */
object JwtConfig {
    private const val secret = "degenhf-ktor-secret-key-change-in-production"
    private const val issuer = "degenhf-ktor"
    private const val audience = "degenhf-users"

    val verifier = io.jsonwebtoken.JwtParserBuilder()
        .setSigningKey(io.jsonwebtoken.security.Keys.hmacShaKeyFor(secret.toByteArray()))
        .setIssuer(issuer)
        .setAudience(audience)
        .build()
}

/**
 * Request/Response data classes
 */
data class RegisterRequest(
    val username: String,
    val password: String
)

data class LoginRequest(
    val username: String,
    val password: String
)