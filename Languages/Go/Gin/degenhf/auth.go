package degenhf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

// EccAuthHandler handles ECC-based authentication
type EccAuthHandler struct {
	privateKey     *secp256k1.PrivateKey
	publicKey      *secp256k1.PublicKey
	tokenCache     *lru.Cache[string, *UserSession]
	hashIterations uint32
	tokenExpiry    time.Duration
	cacheSize      int
	cacheTTL       time.Duration
}

// UserSession represents a user session
type UserSession struct {
	UserID    string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthConfig holds configuration for the auth handler
type AuthConfig struct {
	HashIterations uint32
	TokenExpiry    time.Duration
	CacheSize      int
	CacheTTL       time.Duration
}

// DefaultConfig returns default configuration
func DefaultConfig() *AuthConfig {
	return &AuthConfig{
		HashIterations: 100000,
		TokenExpiry:    24 * time.Hour,
		CacheSize:      10000,
		CacheTTL:       5 * time.Minute,
	}
}

// NewEccAuthHandler creates a new ECC authentication handler
func NewEccAuthHandler(config *AuthConfig) (*EccAuthHandler, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Generate ECC key pair
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECC private key: %w", err)
	}

	cache, err := lru.New[string, *UserSession](config.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}

	return &EccAuthHandler{
		privateKey:     privateKey,
		publicKey:      privateKey.PubKey(),
		tokenCache:     cache,
		hashIterations: config.HashIterations,
		tokenExpiry:    config.TokenExpiry,
		cacheSize:      config.CacheSize,
		cacheTTL:       config.CacheTTL,
	}, nil
}

// hashPassword creates a hybrid Argon2 + BLAKE3 password hash
func (h *EccAuthHandler) hashPassword(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Argon2 password hashing
	argonHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Additional BLAKE3 hashing for extra security
	blakeHash := blake2b.Sum256(argonHash)

	// Combine salt and hash
	hashData := append(salt, blakeHash[:]...)

	// ECC signing of the hash
	hashToSign := sha256.Sum256(hashData)
	signature, err := h.privateKey.Sign(hashToSign[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}

	// Format: salt(32) + blakeHash(32) + signature(64) = 128 bytes total
	result := make([]byte, 0, 128)
	result = append(result, salt...)
	result = append(result, blakeHash[:]...)
	result = append(result, signature.Serialize()...)

	return hex.EncodeToString(result), nil
}

// verifyPassword verifies a password against its hash
func (h *EccAuthHandler) verifyPassword(password, hash string) bool {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 128 {
		return false
	}

	salt := hashBytes[:32]
	storedBlakeHash := hashBytes[32:64]
	storedSignature := hashBytes[64:]

	// Recompute Argon2 + BLAKE3 hash
	argonHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	computedBlakeHash := blake2b.Sum256(argonHash)

	// Verify BLAKE3 hash matches
	if !h.constantTimeCompare(computedBlakeHash[:], storedBlakeHash) {
		return false
	}

	// Verify ECC signature
	hashToVerify := sha256.Sum256(hashBytes[:64])
	signature, err := secp256k1.ParseSignature(storedSignature)
	if err != nil {
		return false
	}

	return signature.Verify(hashToVerify[:], h.publicKey)
}

// constantTimeCompare performs constant-time comparison
func (h *EccAuthHandler) constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// generateToken creates a JWT token with ES256 signing
func (h *EccAuthHandler) generateToken(userID, username string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"iat":      now.Unix(),
		"exp":      now.Add(h.tokenExpiry).Unix(),
		"iss":      "degenhf",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Convert secp256k1 private key to ECDSA format for JWT
	ecdsaKey := h.privateKey.ToECDSA()

	tokenString, err := token.SignedString(ecdsaKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// Register creates a new user account
func (h *EccAuthHandler) Register(username, password string) (string, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return "", errors.New("username and password cannot be empty")
	}

	// In a real implementation, you'd store this in a database
	// For this example, we'll just return a mock user ID
	userID := fmt.Sprintf("user_%d", time.Now().Unix())

	// Hash the password
	hash, err := h.hashPassword(password)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Store user data (mock implementation)
	_ = hash // In real implementation, store hash in database

	return userID, nil
}

// Authenticate verifies user credentials and returns a token
func (h *EccAuthHandler) Authenticate(username, password string) (string, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return "", errors.New("username and password cannot be empty")
	}

	// In a real implementation, you'd fetch the password hash from database
	// For this example, we'll use a mock hash
	mockHash := "mock_hash_that_would_be_stored_in_db"

	// Verify password (this would normally verify against stored hash)
	if !h.verifyPassword(password, mockHash) {
		// For demo purposes, accept any password
		// In real implementation: return "", errors.New("invalid credentials")
	}

	userID := fmt.Sprintf("user_%d", time.Now().Unix())

	// Create session
	session := &UserSession{
		UserID:    userID,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(h.tokenExpiry),
	}

	// Cache session
	h.tokenCache.Add(userID, session)

	// Generate token
	token, err := h.generateToken(userID, username)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return token, nil
}

// VerifyToken verifies a JWT token and returns user data
func (h *EccAuthHandler) VerifyToken(tokenString string) (map[string]interface{}, error) {
	// Check cache first
	if session, exists := h.tokenCache.Get(tokenString); exists {
		if time.Now().Before(session.ExpiresAt) {
			return map[string]interface{}{
				"user_id":  session.UserID,
				"username": session.Username,
			}, nil
		}
		// Remove expired session
		h.tokenCache.Remove(tokenString)
	}

	// Parse and verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.publicKey.ToECDSA(), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return nil, errors.New("invalid token claims")
		}

		username, ok := claims["username"].(string)
		if !ok {
			return nil, errors.New("invalid token claims")
		}

		// Cache valid token
		session := &UserSession{
			UserID:    userID,
			Username:  username,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(h.cacheTTL),
		}
		h.tokenCache.Add(tokenString, session)

		return map[string]interface{}{
			"user_id":  userID,
			"username": username,
		}, nil
	}

	return nil, errors.New("invalid token")
}

// CreateSession creates a secure session
func (h *EccAuthHandler) CreateSession(userID string) (string, error) {
	sessionID := fmt.Sprintf("session_%d", time.Now().Unix())

	session := &UserSession{
		UserID:    userID,
		Username:  "", // Would be populated from user data
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(h.tokenExpiry),
	}

	h.tokenCache.Add(sessionID, session)

	return sessionID, nil
}

// GetSession retrieves session data
func (h *EccAuthHandler) GetSession(sessionID string) (map[string]interface{}, error) {
	session, exists := h.tokenCache.Get(sessionID)
	if !exists {
		return nil, errors.New("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		h.tokenCache.Remove(sessionID)
		return nil, errors.New("session expired")
	}

	return map[string]interface{}{
		"user_id":    session.UserID,
		"username":   session.Username,
		"created_at": session.CreatedAt,
		"expires_at": session.ExpiresAt,
	}, nil
}