package degenhf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEccAuthHandler(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)
	assert.NotNil(t, auth)
	assert.NotNil(t, auth.privateKey)
	assert.NotNil(t, auth.publicKey)
	assert.NotNil(t, auth.tokenCache)
}

func TestEccAuthHandlerWithConfig(t *testing.T) {
	config := &AuthConfig{
		HashIterations: 50000,
		TokenExpiry:    1 * time.Hour,
		CacheSize:      100,
		CacheTTL:       10 * time.Minute,
	}

	auth, err := NewEccAuthHandler(config)
	require.NoError(t, err)
	assert.Equal(t, uint32(50000), auth.hashIterations)
	assert.Equal(t, 1*time.Hour, auth.tokenExpiry)
	assert.Equal(t, 100, auth.cacheSize)
	assert.Equal(t, 10*time.Minute, auth.cacheTTL)
}

func TestRegister(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	userID, err := auth.Register("testuser", "testpass123")
	require.NoError(t, err)
	assert.NotEmpty(t, userID)
	assert.Contains(t, userID, "user_")
}

func TestRegisterEmptyCredentials(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Test empty username
	_, err = auth.Register("", "password")
	assert.Error(t, err)

	// Test empty password
	_, err = auth.Register("username", "")
	assert.Error(t, err)
}

func TestAuthenticate(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Register user first
	userID, err := auth.Register("testuser", "testpass123")
	require.NoError(t, err)

	// Authenticate (mock implementation accepts any password)
	token, err := auth.Authenticate("testuser", "testpass123")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token
	userData, err := auth.VerifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, userData["user_id"])
	assert.Equal(t, "testuser", userData["username"])
}

func TestAuthenticateEmptyCredentials(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Test empty username
	_, err = auth.Authenticate("", "password")
	assert.Error(t, err)

	// Test empty password
	_, err = auth.Authenticate("username", "")
	assert.Error(t, err)
}

func TestVerifyToken(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Create a token
	token, err := auth.generateToken("user123", "testuser")
	require.NoError(t, err)

	// Verify token
	userData, err := auth.VerifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, "user123", userData["user_id"])
	assert.Equal(t, "testuser", userData["username"])
}

func TestVerifyInvalidToken(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Test invalid token
	_, err = auth.VerifyToken("invalid.token.here")
	assert.Error(t, err)

	// Test empty token
	_, err = auth.VerifyToken("")
	assert.Error(t, err)
}

func TestCreateSession(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	sessionID, err := auth.CreateSession("user123")
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID)
	assert.Contains(t, sessionID, "session_")
}

func TestGetSession(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Create session
	sessionID, err := auth.CreateSession("user123")
	require.NoError(t, err)

	// Get session
	sessionData, err := auth.GetSession(sessionID)
	require.NoError(t, err)
	assert.Equal(t, "user123", sessionData["user_id"])
	assert.NotNil(t, sessionData["created_at"])
	assert.NotNil(t, sessionData["expires_at"])
}

func TestGetNonExistentSession(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	_, err = auth.GetSession("nonexistent")
	assert.Error(t, err)
}

func TestGinMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Create a valid token
	token, err := auth.generateToken("user123", "testuser")
	require.NoError(t, err)

	// Test with valid token
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/protected", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	middleware := auth.GinMiddleware()
	middleware(c)

	assert.Equal(t, http.StatusOK, w.Code)

	// Test without authorization header
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/protected", nil)

	middleware(c)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test with invalid token
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/protected", nil)
	c.Request.Header.Set("Authorization", "Bearer invalid.token")

	middleware(c)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegisterHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/register", strings.NewReader(`{"username":"testuser","password":"testpass123"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	auth.RegisterHandler(c)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestLoginHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"testuser","password":"testpass123"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	auth.LoginHandler(c)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestVerifyHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Create valid token and set in context
	token, err := auth.generateToken("user123", "testuser")
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("user_id", "user123")
	c.Set("username", "testuser")
	c.Request = httptest.NewRequest("GET", "/verify", nil)

	auth.VerifyHandler(c)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestProfileHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("user_id", "user123")
	c.Set("username", "testuser")
	c.Request = httptest.NewRequest("GET", "/profile", nil)

	auth.ProfileHandler(c)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHashPassword(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	hash1, err := auth.hashPassword("testpassword")
	require.NoError(t, err)
	assert.NotEmpty(t, hash1)

	hash2, err := auth.hashPassword("testpassword")
	require.NoError(t, err)
	assert.NotEmpty(t, hash2)

	// Hashes should be different due to random salt
	assert.NotEqual(t, hash1, hash2)
}

func TestVerifyPassword(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	password := "testpassword123"
	hash, err := auth.hashPassword(password)
	require.NoError(t, err)

	// Test correct password
	assert.True(t, auth.verifyPassword(password, hash))

	// Test incorrect password
	assert.False(t, auth.verifyPassword("wrongpassword", hash))

	// Test invalid hash
	assert.False(t, auth.verifyPassword(password, "invalidhash"))
}

func BenchmarkHashPassword(b *testing.B) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, _ = auth.hashPassword("benchmarkpassword")
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(b, err)

	hash, _ := auth.hashPassword("benchmarkpassword")

	for i := 0; i < b.N; i++ {
		auth.verifyPassword("benchmarkpassword", hash)
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, _ = auth.generateToken("user123", "testuser")
	}
}

func BenchmarkVerifyToken(b *testing.B) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(b, err)

	token, _ := auth.generateToken("user123", "testuser")

	for i := 0; i < b.N; i++ {
		_, _ = auth.VerifyToken(token)
	}
}