package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/revel/revel/v3"
	"github.com/degenhf/DegenHF/Go/Revel/app/controllers"
	"github.com/degenhf/DegenHF/Go/Revel/app/models"
	_ "github.com/degenhf/DegenHF/Go/Revel/app"
)

func init() {
	revel.Init("dev", "github.com/degenhf/DegenHF/Go/Revel", "")
	models.ClearAllUsers() // Clear any existing test data
}

func TestAuthHandler_Register(t *testing.T) {
	models.ClearAllUsers()

	handler := controllers.NewEccAuthHandler()

	// Test successful registration
	userID, err := handler.Register("testuser", "testpassword123")
	if err != nil {
		t.Fatalf("Expected successful registration, got error: %v", err)
	}
	if userID == "" {
		t.Fatal("Expected non-empty user ID")
	}

	// Test duplicate registration
	_, err = handler.Register("testuser", "differentpassword")
	if err == nil {
		t.Fatal("Expected error for duplicate registration")
	}

	// Test short password
	_, err = handler.Register("user2", "short")
	if err == nil {
		t.Fatal("Expected error for short password")
	}
}

func TestAuthHandler_Authenticate(t *testing.T) {
	models.ClearAllUsers()

	handler := controllers.NewEccAuthHandler()

	// Register user first
	username := "testuser"
	password := "testpassword123"
	_, err := handler.Register(username, password)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Test successful authentication
	token, err := handler.Authenticate(username, password)
	if err != nil {
		t.Fatalf("Expected successful authentication, got error: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// Test wrong password
	_, err = handler.Authenticate(username, "wrongpassword")
	if err == nil {
		t.Fatal("Expected error for wrong password")
	}

	// Test non-existent user
	_, err = handler.Authenticate("nonexistent", password)
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
}

func TestAuthHandler_VerifyToken(t *testing.T) {
	models.ClearAllUsers()

	handler := controllers.NewEccAuthHandler()

	// Register and authenticate user
	username := "testuser"
	password := "testpassword123"
	_, err := handler.Register(username, password)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	token, err := handler.Authenticate(username, password)
	if err != nil {
		t.Fatalf("Failed to authenticate user: %v", err)
	}

	// Test successful token verification
	session, err := handler.VerifyToken(token)
	if err != nil {
		t.Fatalf("Expected successful token verification, got error: %v", err)
	}
	if session.Username != username {
		t.Errorf("Expected username %s, got %s", username, session.Username)
	}

	// Test invalid token
	_, err = handler.VerifyToken("invalid.token.here")
	if err == nil {
		t.Fatal("Expected error for invalid token")
	}
}

func TestAuthHandler_GetUserProfile(t *testing.T) {
	models.ClearAllUsers()

	handler := controllers.NewEccAuthHandler()

	// Register user
	username := "testuser"
	password := "testpassword123"
	userID, err := handler.Register(username, password)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Test successful profile retrieval
	profile, err := handler.GetUserProfile(userID)
	if err != nil {
		t.Fatalf("Expected successful profile retrieval, got error: %v", err)
	}
	if profile.Username != username {
		t.Errorf("Expected username %s, got %s", username, profile.Username)
	}

	// Test non-existent user
	_, err = handler.GetUserProfile("invalid_user_id")
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
}

func TestAuth_Register(t *testing.T) {
	models.ClearAllUsers()

	// Create test request
	req := controllers.RegisterRequest{
		Username: "testuser",
		Password: "testpassword123",
	}
	reqBody, _ := json.Marshal(req)

	// Create HTTP request
	httpReq, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Create controller and call method
	c := &controllers.Auth{}
	c.T = t
	c.Request = revel.NewRequest(httpReq)
	c.Response = revel.NewResponse(w)

	// Call the method
	result := c.Register()

	// Check result
	if result == nil {
		t.Fatal("Expected result from Register method")
	}
}

func TestAuth_Authenticate(t *testing.T) {
	models.ClearAllUsers()

	// Register user first
	handler := controllers.NewEccAuthHandler()
	_, err := handler.Register("testuser", "testpassword123")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Create test request
	req := controllers.AuthenticateRequest{
		Username: "testuser",
		Password: "testpassword123",
	}
	reqBody, _ := json.Marshal(req)

	// Create HTTP request
	httpReq, _ := http.NewRequest("POST", "/api/auth/authenticate", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Create controller and call method
	c := &controllers.Auth{}
	c.T = t
	c.Request = revel.NewRequest(httpReq)
	c.Response = revel.NewResponse(w)

	// Call the method
	result := c.Authenticate()

	// Check result
	if result == nil {
		t.Fatal("Expected result from Authenticate method")
	}
}

func TestAuth_Health(t *testing.T) {
	// Create HTTP request
	httpReq, _ := http.NewRequest("GET", "/api/auth/health", nil)

	// Create response recorder
	w := httptest.NewRecorder()

	// Create controller and call method
	c := &controllers.Auth{}
	c.T = t
	c.Request = revel.NewRequest(httpReq)
	c.Response = revel.NewResponse(w)

	// Call the method
	result := c.Health()

	// Check result
	if result == nil {
		t.Fatal("Expected result from Health method")
	}
}