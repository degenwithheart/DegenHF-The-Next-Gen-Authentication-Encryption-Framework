package com.degenhf.auth

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.cache.CacheManager
import org.springframework.cache.concurrent.ConcurrentMapCacheManager
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.http.MediaType
import com.fasterxml.jackson.databind.ObjectMapper
import java.time.Instant

/**
 * Unit tests for ECC Auth Handler
 */
@SpringBootTest
@TestPropertySource(properties = ["spring.main.allow-bean-definition-overriding=true"])
class EccAuthHandlerTest {

    @Autowired
    private lateinit var authHandler: EccAuthHandler

    @Autowired
    private lateinit var cacheManager: CacheManager

    @BeforeEach
    fun setup() {
        // Clear cache before each test
        cacheManager.getCache("tokenCache")?.clear()
    }

    @Test
    fun `test user registration success`() {
        val username = "testuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        val userId = authHandler.register(username, password)

        assertNotNull(userId)
        assertTrue(userId.startsWith("user_"))
    }

    @Test
    fun `test user registration with existing username fails`() {
        val username = "existinguser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        authHandler.register(username, password)

        val exception = assertThrows(RuntimeException::class.java) {
            authHandler.register(username, "differentpassword")
        }

        assertEquals("User already exists", exception.message)
    }

    @Test
    fun `test user registration with short password fails`() {
        val username = "testuser_${System.currentTimeMillis()}"
        val password = "short"

        val exception = assertThrows(IllegalArgumentException::class.java) {
            authHandler.register(username, password)
        }

        assertTrue(exception.message?.contains("Password must be at least 8 characters") == true)
    }

    @Test
    fun `test authentication success`() {
        val username = "authuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        authHandler.register(username, password)
        val token = authHandler.authenticate(username, password)

        assertNotNull(token)
        assertTrue(token.isNotBlank())
    }

    @Test
    fun `test authentication with wrong password fails`() {
        val username = "authuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        authHandler.register(username, password)

        val exception = assertThrows(RuntimeException::class.java) {
            authHandler.authenticate(username, "wrongpassword")
        }

        assertEquals("Invalid credentials", exception.message)
    }

    @Test
    fun `test token verification success`() {
        val username = "verifyuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        authHandler.register(username, password)
        val token = authHandler.authenticate(username, password)
        val session = authHandler.verifyToken(token)

        assertNotNull(session)
        assertEquals(username, session.username)
        assertTrue(session.expiresAt.isAfter(Instant.now()))
    }

    @Test
    fun `test token verification with invalid token fails`() {
        val exception = assertThrows(RuntimeException::class.java) {
            authHandler.verifyToken("invalid.token.here")
        }

        assertEquals("Invalid token", exception.message)
    }

    @Test
    fun `test get user profile success`() {
        val username = "profileuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        val userId = authHandler.register(username, password)
        val profile = authHandler.getUserProfile(userId)

        assertNotNull(profile)
        assertEquals(userId, profile.userId)
        assertEquals(username, profile.username)
    }

    @Test
    fun `test get user profile with invalid user fails`() {
        val exception = assertThrows(RuntimeException::class.java) {
            authHandler.getUserProfile("invalid_user_id")
        }

        assertEquals("User not found", exception.message)
    }
}

/**
 * Integration tests for Auth Controller
 */
@SpringBootTest
@TestPropertySource(properties = ["spring.main.allow-bean-definition-overriding=true"])
class AuthControllerIntegrationTest {

    @Autowired
    private lateinit var webApplicationContext: WebApplicationContext

    private lateinit var mockMvc: MockMvc
    private lateinit var objectMapper: ObjectMapper

    @BeforeEach
    fun setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build()
        objectMapper = ObjectMapper()
    }

    @Test
    fun `test register endpoint success`() {
        val username = "testuser_${System.currentTimeMillis()}"
        val request = RegisterRequest(username, "testpassword123")

        mockMvc.perform(post("/api/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.userId").exists())
    }

    @Test
    fun `test register endpoint with invalid data fails`() {
        val request = RegisterRequest("", "short")

        mockMvc.perform(post("/api/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.success").value(false))
    }

    @Test
    fun `test authenticate endpoint success`() {
        val username = "authuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        // First register the user
        val registerRequest = RegisterRequest(username, password)
        mockMvc.perform(post("/api/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)))
            .andExpect(status().isOk)

        // Then authenticate
        val authRequest = AuthenticateRequest(username, password)
        mockMvc.perform(post("/api/auth/authenticate")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(authRequest)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.token").exists())
    }

    @Test
    fun `test authenticate endpoint with wrong credentials fails`() {
        val authRequest = AuthenticateRequest("nonexistent", "wrongpassword")

        mockMvc.perform(post("/api/auth/authenticate")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(authRequest)))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.success").value(false))
    }

    @Test
    fun `test verify endpoint success`() {
        val username = "verifyuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        // Register and authenticate to get token
        val registerRequest = RegisterRequest(username, password)
        mockMvc.perform(post("/api/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)))
            .andExpect(status().isOk)

        val authRequest = AuthenticateRequest(username, password)
        val authResult = mockMvc.perform(post("/api/auth/authenticate")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(authRequest)))
            .andExpect(status().isOk)
            .andReturn()

        val authResponse = objectMapper.readTree(authResult.response.contentAsString)
        val token = authResponse.get("token").asText()

        // Verify token
        val verifyRequest = VerifyRequest(token)
        mockMvc.perform(post("/api/auth/verify")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(verifyRequest)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.username").value(username))
    }

    @Test
    fun `test verify endpoint with invalid token fails`() {
        val verifyRequest = VerifyRequest("invalid.token")

        mockMvc.perform(post("/api/auth/verify")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(verifyRequest)))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.success").value(false))
    }

    @Test
    fun `test profile endpoint success`() {
        val username = "profileuser_${System.currentTimeMillis()}"
        val password = "testpassword123"

        // Register and authenticate to get token
        val registerRequest = RegisterRequest(username, password)
        mockMvc.perform(post("/api/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)))
            .andExpect(status().isOk)

        val authRequest = AuthenticateRequest(username, password)
        val authResult = mockMvc.perform(post("/api/auth/authenticate")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(authRequest)))
            .andExpect(status().isOk)
            .andReturn()

        val authResponse = objectMapper.readTree(authResult.response.contentAsString)
        val token = authResponse.get("token").asText()

        // Get profile
        mockMvc.perform(get("/api/auth/profile")
            .header("Authorization", "Bearer $token"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.profile.username").value(username))
    }

    @Test
    fun `test profile endpoint without token fails`() {
        mockMvc.perform(get("/api/auth/profile"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `test health endpoint success`() {
        mockMvc.perform(get("/api/auth/health"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("healthy"))
            .andExpect(jsonPath("$.service").value("ecc-auth"))
    }
}