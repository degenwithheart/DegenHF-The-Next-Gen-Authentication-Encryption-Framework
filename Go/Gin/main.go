package main

import (
	"log"
	"net/http"

	"github.com/degenwithheart/DegenHF/Go/Gin/degenhf"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize ECC auth handler with default config
	auth, err := degenhf.NewEccAuthHandler(nil)
	if err != nil {
		log.Fatal("Failed to initialize auth handler:", err)
	}

	// Create Gin router
	r := gin.Default()

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Public routes
	r.POST("/register", auth.RegisterHandler)
	r.POST("/login", auth.LoginHandler)

	// Protected routes (require authentication)
	protected := r.Group("/api")
	protected.Use(auth.GinMiddleware())
	{
		protected.GET("/verify", auth.VerifyHandler)
		protected.GET("/profile", auth.ProfileHandler)
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"service": "DegenHF-Gin",
		})
	})

	log.Println("🚀 DegenHF-Gin server starting on :8080")
	log.Println("📖 API Documentation:")
	log.Println("   POST /register - Register new user")
	log.Println("   POST /login    - Login user")
	log.Println("   GET  /api/verify  - Verify token (protected)")
	log.Println("   GET  /api/profile - Get user profile (protected)")
	log.Println("   GET  /health   - Health check")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}