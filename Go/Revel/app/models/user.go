package models

import (
	"sync"
	"time"
)

// UserData represents user information stored in memory
type UserData struct {
	UserID       string    `json:"userId"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	Salt         string    `json:"salt"`
	ECCPrivateKey string   `json:"eccPrivateKey"`
	ECCPublicKey  string   `json:"eccPublicKey"`
	CreatedAt    time.Time `json:"createdAt"`
}

// Global storage (in-memory for demo - replace with database in production)
var (
	usersMu sync.RWMutex
	users   = make(map[string]*UserData) // username -> user data
	userIDs = make(map[string]*UserData) // userID -> user data
)

// InitStorage initializes the storage system
func InitStorage() {
	// In production, initialize database connection here
}

// StoreUser stores a user in memory
func StoreUser(userData *UserData) {
	usersMu.Lock()
	defer usersMu.Unlock()
	users[userData.Username] = userData
	userIDs[userData.UserID] = userData
}

// GetUserByUsername retrieves a user by username
func GetUserByUsername(username string) (*UserData, bool) {
	usersMu.RLock()
	defer usersMu.RUnlock()
	user, exists := users[username]
	return user, exists
}

// GetUserByUserID retrieves a user by user ID
func GetUserByUserID(userID string) (*UserData, bool) {
	usersMu.RLock()
	defer usersMu.RUnlock()
	user, exists := userIDs[userID]
	return user, exists
}

// UserExists checks if a user exists by username
func UserExists(username string) bool {
	usersMu.RLock()
	defer usersMu.RUnlock()
	_, exists := users[username]
	return exists
}

// GetAllUsers returns all users (for testing/admin purposes)
func GetAllUsers() map[string]*UserData {
	usersMu.RLock()
	defer usersMu.RUnlock()
	result := make(map[string]*UserData)
	for k, v := range users {
		result[k] = v
	}
	return result
}

// ClearAllUsers clears all users (for testing)
func ClearAllUsers() {
	usersMu.Lock()
	defer usersMu.Unlock()
	users = make(map[string]*UserData)
	userIDs = make(map[string]*UserData)
}