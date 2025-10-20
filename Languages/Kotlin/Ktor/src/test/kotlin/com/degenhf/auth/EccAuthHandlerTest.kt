package com.degenhf.auth

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.assertThrows
import java.time.Duration

class EccAuthHandlerTest {

    private lateinit var authHandler: EccAuthHandler

    @BeforeEach
    fun setup() {
        val options = EccAuthOptions(
            hashIterations = 1000, // Lower for faster tests
            tokenExpiry = Duration.ofMinutes(5),
            cacheSize = 100,
            cacheTtl = Duration.ofSeconds(30)
        )
        authHandler = EccAuthHandler(options)
    }

    @Test
    fun `test user registration and authentication`() {
        val username = "testuser"
        val password = "testpassword123"

        // Register user
        val userId = authHandler.register(username, password)
        assertNotNull(userId)
        assertTrue(userId.startsWith("user_"))

        // Authenticate user
        val token = authHandler.authenticate(username, password)
        assertNotNull(token)
        assertTrue(token.isNotBlank())

        // Verify token
        val session = authHandler.verifyToken(token)
        assertNotNull(session)
        assertEquals(userId, session.userId)
        assertEquals(username, session.username)
    }

    @Test
    fun `test invalid credentials`() {
        val username = "testuser"
        val password = "testpassword123"

        // Register user
        authHandler.register(username, password)

        // Try to authenticate with wrong password
        assertThrows<RuntimeException> {
            authHandler.authenticate(username, "wrongpassword")
        }

        // Try to authenticate non-existent user
        assertThrows<RuntimeException> {
            authHandler.authenticate("nonexistent", password)
        }
    }

    @Test
    fun `test duplicate user registration`() {
        val username = "testuser"
        val password = "testpassword123"

        // Register user first time
        authHandler.register(username, password)

        // Try to register same user again
        assertThrows<RuntimeException> {
            authHandler.register(username, "differentpassword")
        }
    }

    @Test
    fun `test invalid registration input`() {
        // Blank username
        assertThrows<IllegalArgumentException> {
            authHandler.register("", "password123")
        }

        // Short password
        assertThrows<IllegalArgumentException> {
            authHandler.register("username", "short")
        }
    }

    @Test
    fun `test user profile retrieval`() {
        val username = "testuser"
        val password = "testpassword123"

        // Register and authenticate user
        val userId = authHandler.register(username, password)
        val token = authHandler.authenticate(username, password)
        val session = authHandler.verifyToken(token)

        // Get user profile
        val profile = authHandler.getUserProfile(userId)
        assertNotNull(profile)
        assertEquals(userId, profile.userId)
        assertEquals(username, profile.username)
    }

    @Test
    fun `test session management`() {
        val username = "testuser"
        val password = "testpassword123"

        // Register user
        val userId = authHandler.register(username, password)

        // Create session
        val session = authHandler.createSession(userId)
        assertNotNull(session)
        assertEquals(userId, session.userId)
        assertEquals(username, session.username)

        // Get session
        val retrievedSession = authHandler.getSession(session.sessionId)
        assertNotNull(retrievedSession)
        assertEquals(session.sessionId, retrievedSession?.sessionId)
    }

    @Test
    fun `test token verification caching`() {
        val username = "testuser"
        val password = "testpassword123"

        // Register and authenticate user
        authHandler.register(username, password)
        val token = authHandler.authenticate(username, password)

        // First verification (should cache)
        val session1 = authHandler.verifyToken(token)
        assertNotNull(session1)

        // Second verification (should use cache)
        val session2 = authHandler.verifyToken(token)
        assertNotNull(session2)
        assertEquals(session1.sessionId, session2.sessionId)
    }
}