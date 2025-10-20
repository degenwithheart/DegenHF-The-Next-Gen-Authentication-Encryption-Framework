package com.degenhf.eccauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static org.junit.jupiter.api.Assertions.*;

@SpringJUnitConfig
class EccAuthServiceTest {

    private EccAuthService authService;

    @BeforeEach
    void setUp() throws Exception {
        authService = new EccAuthService();
    }

    @Test
    void testRegister() throws Exception {
        String userId = authService.register("testuser", "testpass123");
        assertNotNull(userId);
        assertFalse(userId.isEmpty());
    }

    @Test
    void testRegisterDuplicateUser() throws Exception {
        authService.register("testuser", "testpass123");
        assertThrows(IllegalArgumentException.class, () -> {
            authService.register("testuser", "differentpass");
        });
    }

    @Test
    void testRegisterInvalidPassword() {
        assertThrows(IllegalArgumentException.class, () -> {
            authService.register("testuser", "short");
        });
    }

    @Test
    void testAuthenticate() throws Exception {
        authService.register("testuser", "testpass123");
        String token = authService.authenticate("testuser", "testpass123");
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void testAuthenticateInvalidUser() {
        assertThrows(SecurityException.class, () -> {
            authService.authenticate("nonexistent", "testpass123");
        });
    }

    @Test
    void testAuthenticateInvalidPassword() throws Exception {
        authService.register("testuser", "testpass123");
        assertThrows(SecurityException.class, () -> {
            authService.authenticate("testuser", "wrongpass");
        });
    }

    @Test
    void testVerifyToken() throws Exception {
        authService.register("testuser", "testpass123");
        String token = authService.authenticate("testuser", "testpass123");
        EccAuthService.UserData user = authService.verifyToken(token);
        assertNotNull(user);
        assertEquals("testuser", user.getUsername());
    }

    @Test
    void testVerifyInvalidToken() {
        assertThrows(SecurityException.class, () -> {
            authService.verifyToken("invalid.token.here");
        });
    }

    @Test
    void testCreateSession() throws Exception {
        authService.register("testuser", "testpass123");
        String token = authService.authenticate("testuser", "testpass123");
        EccAuthService.UserData user = authService.verifyToken(token);

        EccAuthService.SessionData session = authService.createSession(user.getId());
        assertNotNull(session);
        assertNotNull(session.getSessionId());
        assertEquals(user.getId(), session.getUserId());
    }

    @Test
    void testGetSession() throws Exception {
        authService.register("testuser", "testpass123");
        String token = authService.authenticate("testuser", "testpass123");
        EccAuthService.UserData user = authService.verifyToken(token);

        EccAuthService.SessionData created = authService.createSession(user.getId());
        EccAuthService.SessionData retrieved = authService.getSession(created.getSessionId());

        assertNotNull(retrieved);
        assertEquals(created.getSessionId(), retrieved.getSessionId());
        assertEquals(created.getUserId(), retrieved.getUserId());
    }
}