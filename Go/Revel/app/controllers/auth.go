package controllers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"github.com/revel/revel/v3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

// Auth controller for ECC-based authentication
type Auth struct {
	*revel.Controller
}

// Global auth handler instance
var authHandler *EccAuthHandler

// InitAuthHandler initializes the global auth handler
func InitAuthHandler() {
	authHandler = NewEccAuthHandler()
}

// EccAuthHandler handles ECC-based authentication
type EccAuthHandler struct {
	cache *cache.Cache
}

// NewEccAuthHandler creates a new ECC auth handler
func NewEccAuthHandler() *EccAuthHandler {
	return &EccAuthHandler{
		cache: cache.New(5*time.Minute, 10*time.Minute),
	}
}

// UserData represents user information
type UserData struct {
	UserID       string    `json:"userId"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	Salt         string    `json:"salt"`
	ECCPrivateKey string   `json:"eccPrivateKey"`
	ECCPublicKey  string   `json:"eccPublicKey"`
	CreatedAt    time.Time `json:"createdAt"`
}

// UserSession represents a user session
type UserSession struct {
	SessionID string    `json:"sessionId"`
	UserID    string    `json:"userId"`
	Username  string    `json:"username"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// UserProfile represents user profile information
type UserProfile struct {
	UserID    string    `json:"userId"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	LastLogin time.Time `json:"lastLogin"`
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,min=8"`
}

// RegisterResponse represents a registration response
type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	UserID  string `json:"userId,omitempty"`
}

// AuthenticateRequest represents an authentication request
type AuthenticateRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// AuthenticateResponse represents an authentication response
type AuthenticateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

// VerifyRequest represents a token verification request
type VerifyRequest struct {
	Token string `json:"token" validate:"required"`
}

// VerifyResponse represents a token verification response
type VerifyResponse struct {
	Success  bool      `json:"success"`
	Message  string    `json:"message"`
	UserID   string    `json:"userId,omitempty"`
	Username string    `json:"username,omitempty"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// ProfileResponse represents a profile response
type ProfileResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Profile *UserProfile `json:"profile,omitempty"`
}

// Register handles user registration
func (c Auth) Register() revel.Result {
	var req RegisterRequest
	if err := json.NewDecoder(c.Request.GetBody()).Decode(&req); err != nil {
		return c.RenderJSON(RegisterResponse{
			Success: false,
			Message: "Invalid JSON request",
		})
	}

	// Validate request
	c.Validation.Required(req.Username).Message("Username is required")
	c.Validation.MinSize(req.Username, 3).Message("Username must be at least 3 characters")
	c.Validation.MaxSize(req.Username, 50).Message("Username must be at most 50 characters")
	c.Validation.Required(req.Password).Message("Password is required")
	c.Validation.MinSize(req.Password, 8).Message("Password must be at least 8 characters")

	if c.Validation.HasErrors() {
		return c.RenderJSON(RegisterResponse{
			Success: false,
			Message: c.Validation.Errors[0].Message,
		})
	}

	userID, err := authHandler.Register(req.Username, req.Password)
	if err != nil {
		return c.RenderJSON(RegisterResponse{
			Success: false,
			Message: err.Error(),
		})
	}

	return c.RenderJSON(RegisterResponse{
		Success: true,
		Message: "User registered successfully",
		UserID:  userID,
	})
}

// Authenticate handles user authentication
func (c Auth) Authenticate() revel.Result {
	var req AuthenticateRequest
	if err := json.NewDecoder(c.Request.GetBody()).Decode(&req); err != nil {
		return c.RenderJSON(AuthenticateResponse{
			Success: false,
			Message: "Invalid JSON request",
		})
	}

	// Validate request
	c.Validation.Required(req.Username).Message("Username is required")
	c.Validation.Required(req.Password).Message("Password is required")

	if c.Validation.HasErrors() {
		return c.RenderJSON(AuthenticateResponse{
			Success: false,
			Message: c.Validation.Errors[0].Message,
		})
	}

	token, err := authHandler.Authenticate(req.Username, req.Password)
	if err != nil {
		return c.RenderJSON(AuthenticateResponse{
			Success: false,
			Message: err.Error(),
		})
	}

	return c.RenderJSON(AuthenticateResponse{
		Success: true,
		Message: "Authentication successful",
		Token:   token,
	})
}

// Verify handles token verification
func (c Auth) Verify() revel.Result {
	var req VerifyRequest
	if err := json.NewDecoder(c.Request.GetBody()).Decode(&req); err != nil {
		return c.RenderJSON(VerifyResponse{
			Success: false,
			Message: "Invalid JSON request",
		})
	}

	// Validate request
	c.Validation.Required(req.Token).Message("Token is required")

	if c.Validation.HasErrors() {
		return c.RenderJSON(VerifyResponse{
			Success: false,
			Message: c.Validation.Errors[0].Message,
		})
	}

	session, err := authHandler.VerifyToken(req.Token)
	if err != nil {
		return c.RenderJSON(VerifyResponse{
			Success: false,
			Message: err.Error(),
		})
	}

	return c.RenderJSON(VerifyResponse{
		Success:  true,
		Message:  "Token is valid",
		UserID:   session.UserID,
		Username: session.Username,
		ExpiresAt: session.ExpiresAt,
	})
}

// Profile handles user profile retrieval
func (c Auth) Profile() revel.Result {
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return c.RenderJSON(ProfileResponse{
			Success: false,
			Message: "Authorization header required",
		})
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	session, err := authHandler.VerifyToken(token)
	if err != nil {
		return c.RenderJSON(ProfileResponse{
			Success: false,
			Message: err.Error(),
		})
	}

	profile, err := authHandler.GetUserProfile(session.UserID)
	if err != nil {
		return c.RenderJSON(ProfileResponse{
			Success: false,
			Message: err.Error(),
		})
	}

	return c.RenderJSON(ProfileResponse{
		Success: true,
		Message: "Profile retrieved successfully",
		Profile: profile,
	})
}

// Health handles health check
func (c Auth) Health() revel.Result {
	return c.RenderJSON(map[string]string{
		"status":  "healthy",
		"service": "ecc-auth",
	})
}

// Register implements the ECC auth handler methods

// Register creates a new user with ECC-secured password hashing
func (h *EccAuthHandler) Register(username, password string) (string, error) {
	if len(username) < 3 || len(username) > 50 {
		return "", fmt.Errorf("username must be between 3 and 50 characters")
	}
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}

	// Check if user already exists
	if models.UserExists(username) {
		return "", fmt.Errorf("user already exists")
	}

	// Generate ECC key pair
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate ECC key pair: %w", err)
	}
	publicKey := privateKey.PubKey()

	// Generate secure random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Argon2 password hashing
	argon2Hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Additional BLAKE3 hashing
	hasher, _ := blake2b.New256(nil)
	hasher.Write(argon2Hash)
	finalHash := hasher.Sum(nil)

	// Create user data
	userID := fmt.Sprintf("user_%d_%d", time.Now().Unix(), rand.Int63n(1000))
	userData := UserData{
		UserID:       userID,
		Username:     username,
		PasswordHash: base64.StdEncoding.EncodeToString(finalHash),
		Salt:         base64.StdEncoding.EncodeToString(salt),
		ECCPrivateKey: base64.StdEncoding.EncodeToString(privateKey.Serialize()),
		ECCPublicKey:  base64.StdEncoding.EncodeToString(publicKey.SerializeCompressed()),
		CreatedAt:    time.Now(),
	}

	// Store user (in-memory for demo)
	models.StoreUser(&userData)

	revel.AppLog.Info("User registered successfully", "username", username, "userId", userID)
	return userID, nil
}

// Authenticate verifies user credentials and returns JWT token
func (h *EccAuthHandler) Authenticate(username, password string) (string, error) {
	userData, exists := models.GetUserByUsername(username)
	if !exists {
		return "", fmt.Errorf("user not found")
	}

	// Verify password using constant-time comparison
	salt, _ := base64.StdEncoding.DecodeString(userData.Salt)
	argon2Hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	hasher, _ := blake2b.New256(nil)
	hasher.Write(argon2Hash)
	computedHash := hasher.Sum(nil)

	storedHash, _ := base64.StdEncoding.DecodeString(userData.PasswordHash)
	if !constantTimeCompare(computedHash, storedHash) {
		return "", fmt.Errorf("invalid credentials")
	}

	// Create JWT token
	now := time.Now()
	expiry := now.Add(24 * time.Hour)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      userData.UserID,
		"username": userData.Username,
		"iat":      now.Unix(),
		"exp":      expiry.Unix(),
	})

	// Sign with a derived key from ECC private key
	keyData, _ := base64.StdEncoding.DecodeString(userData.ECCPrivateKey)
	signingKey := sha256.Sum256(keyData[:32]) // Use first 32 bytes as HMAC key

	tokenString, err := token.SignedString(signingKey[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	revel.AppLog.Info("User authenticated successfully", "username", username)
	return tokenString, nil
}

// VerifyToken verifies JWT token and returns user session
func (h *EccAuthHandler) VerifyToken(tokenString string) (*UserSession, error) {
	// Check cache first
	if cached, found := h.cache.Get(tokenString); found {
		if session, ok := cached.(*UserSession); ok && session.ExpiresAt.After(time.Now()) {
			return session, nil
		}
	}

	// Parse token without verification first to get user ID
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return nil, nil // We'll verify manually
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token format")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID in token")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username in token")
	}

	// Get user data to verify signature
	userData, exists := models.GetUserByUserID(userID)
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	// Verify token with user's ECC-derived key
	keyData, _ := base64.StdEncoding.DecodeString(userData.ECCPrivateKey)
	signingKey := sha256.Sum256(keyData[:32])

	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return signingKey[:], nil
	})
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Create session
	session := &UserSession{
		SessionID: fmt.Sprintf("session_%d", time.Now().Unix()),
		UserID:    userID,
		Username:  username,
		Token:     tokenString,
		CreatedAt: time.Now(),
		ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
	}

	// Cache the session
	h.cache.Set(tokenString, session, time.Until(session.ExpiresAt))

	return session, nil
}

// GetUserProfile retrieves user profile information
func (h *EccAuthHandler) GetUserProfile(userID string) (*UserProfile, error) {
	userData, exists := models.GetUserByUserID(userID)
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return &UserProfile{
		UserID:    userData.UserID,
		Username:  userData.Username,
		CreatedAt: userData.CreatedAt,
		LastLogin: time.Now(), // In production, track this properly
	}, nil
}

// constantTimeCompare performs constant-time comparison
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}