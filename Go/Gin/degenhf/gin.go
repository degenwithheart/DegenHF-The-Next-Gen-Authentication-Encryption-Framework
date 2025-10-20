package degenhf

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// GinMiddleware returns Gin middleware for authentication
func (h *EccAuthHandler) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>" format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		token := tokenParts[1]

		// Verify token
		userData, err := h.VerifyToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set user data in context
		c.Set("user_id", userData["user_id"])
		c.Set("username", userData["username"])

		c.Next()
	}
}

// RegisterHandler handles user registration
func (h *EccAuthHandler) RegisterHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := h.Register(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user_id":  userID,
		"message": "User registered successfully",
	})
}

// LoginHandler handles user authentication
func (h *EccAuthHandler) LoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := h.Authenticate(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"message": "Login successful",
	})
}

// VerifyHandler verifies token and returns user info
func (h *EccAuthHandler) VerifyHandler(c *gin.Context) {
	userData, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	username, _ := c.Get("username")

	c.JSON(http.StatusOK, gin.H{
		"user_id":  userData,
		"username": username,
		"message": "Token is valid",
	})
}

// ProfileHandler returns user profile (protected route example)
func (h *EccAuthHandler) ProfileHandler(c *gin.Context) {
	userData, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	username, _ := c.Get("username")

	c.JSON(http.StatusOK, gin.H{
		"user_id":  userData,
		"username": username,
		"profile": gin.H{
			"email":    "user@example.com", // Mock data
			"role":     "user",
			"created":  "2024-01-01",
		},
	})
}