package main

import (
	"log"
	"net/http"

	"github.com/degenwithheart/DegenHF/Go/Echo/degenhf"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	// Initialize ECC auth handler with default config
	auth, err := degenhf.NewEccAuthHandler(nil)
	if err != nil {
		log.Fatal("Failed to initialize auth handler:", err)
	}

	// Create Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Public routes
	e.POST("/register", auth.RegisterHandler)
	e.POST("/login", auth.LoginHandler)

	// Protected routes (require authentication)
	api := e.Group("/api")
	api.Use(auth.EchoMiddleware())
	{
		api.GET("/verify", auth.VerifyHandler)
		api.GET("/profile", auth.ProfileHandler)
	}

	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":  "healthy",
			"service": "DegenHF-Echo",
		})
	})

	log.Println("🚀 DegenHF-Echo server starting on :8080")
	log.Println("📖 API Documentation:")
	log.Println("   POST /register - Register new user")
	log.Println("   POST /login    - Login user")
	log.Println("   GET  /api/verify  - Verify token (protected)")
	log.Println("   GET  /api/profile - Get user profile (protected)")
	log.Println("   GET  /health   - Health check")

	if err := e.Start(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}