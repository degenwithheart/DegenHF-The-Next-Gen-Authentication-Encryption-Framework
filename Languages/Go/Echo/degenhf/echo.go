package degenhf

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// EchoMiddleware returns Echo middleware for authentication
func (h *EccAuthHandler) EchoMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authorization header required"})
			}

			// Extract token from "Bearer <token>" format
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid authorization header format"})
			}

			token := tokenParts[1]

			// Verify token
			userData, err := h.VerifyToken(token)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			}

			// Set user data in context
			c.Set("user_id", userData["user_id"])
			c.Set("username", userData["username"])

			return next(c)
		}
	}
}

// RegisterHandler handles user registration
func (h *EccAuthHandler) RegisterHandler(c echo.Context) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username and password are required"})
	}

	userID, err := h.Register(req.Username, req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"user_id":  userID,
		"message": "User registered successfully",
	})
}

// LoginHandler handles user authentication
func (h *EccAuthHandler) LoginHandler(c echo.Context) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username and password are required"})
	}

	token, err := h.Authenticate(req.Username, req.Password)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":   token,
		"message": "Login successful",
	})
}

// VerifyHandler verifies token and returns user info
func (h *EccAuthHandler) VerifyHandler(c echo.Context) error {
	userID := c.Get("user_id")
	if userID == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}

	username := c.Get("username")
	if username == nil {
		username = ""
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"user_id":  userID,
		"username": username,
		"message": "Token is valid",
	})
}

// ProfileHandler returns user profile (protected route example)
func (h *EccAuthHandler) ProfileHandler(c echo.Context) error {
	userID := c.Get("user_id")
	if userID == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}

	username := c.Get("username")
	if username == nil {
		username = ""
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"user_id":  userID,
		"username": username,
		"profile": map[string]interface{}{
			"email":   "user@example.com", // Mock data
			"role":    "user",
			"created": "2024-01-01",
		},
	})
}