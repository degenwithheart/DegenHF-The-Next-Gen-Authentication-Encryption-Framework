package degenhf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
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

func TestEchoMiddleware(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	// Create a valid token
	token, err := auth.generateToken("user123", "testuser")
	require.NoError(t, err)

	// Test with valid token
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := auth.EchoMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err = handler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Test without authorization header
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)

	handler = auth.EchoMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err = handler(c)
	assert.Error(t, err) // Echo returns error for JSON responses in middleware

	// Test with invalid token
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid.token")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)

	handler = auth.EchoMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err = handler(c)
	assert.Error(t, err)
}

func TestRegisterHandler(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"username":"testuser","password":"testpass123"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = auth.RegisterHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestLoginHandler(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"testuser","password":"testpass123"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = auth.LoginHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestVerifyHandler(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user_id", "user123")
	c.Set("username", "testuser")

	err = auth.VerifyHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestProfileHandler(t *testing.T) {
	auth, err := NewEccAuthHandler(nil)
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user_id", "user123")
	c.Set("username", "testuser")

	err = auth.ProfileHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
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