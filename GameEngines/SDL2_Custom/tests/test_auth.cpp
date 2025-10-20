#include "DegenHFECCAuthHandler.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

void testUserRegistration(DegenHF::ECCAuthHandler& auth) {
    std::cout << "Testing user registration..." << std::endl;

    // Test successful registration
    auto result1 = auth.registerUser("testuser1", "password123");
    assert(result1.success && "Registration should succeed");
    assert(!result1.userId.empty() && "User ID should not be empty");
    std::cout << "✓ Registration successful" << std::endl;

    // Test duplicate registration
    auto result2 = auth.registerUser("testuser1", "password456");
    assert(!result2.success && "Duplicate registration should fail");
    std::cout << "✓ Duplicate registration rejected" << std::endl;

    // Test invalid input
    auto result3 = auth.registerUser("", "password123");
    assert(!result3.success && "Empty username should fail");
    std::cout << "✓ Empty username rejected" << std::endl;

    auto result4 = auth.registerUser("user2", "");
    assert(!result4.success && "Empty password should fail");
    std::cout << "✓ Empty password rejected" << std::endl;

    auto result5 = auth.registerUser("us", "password123");
    assert(!result5.success && "Short username should fail");
    std::cout << "✓ Short username rejected" << std::endl;

    auto result6 = auth.registerUser("user3", "12345");
    assert(!result6.success && "Short password should fail");
    std::cout << "✓ Short password rejected" << std::endl;
}

void testUserAuthentication(DegenHF::ECCAuthHandler& auth) {
    std::cout << "Testing user authentication..." << std::endl;

    // Register a user first
    auto regResult = auth.registerUser("testuser2", "password123");
    assert(regResult.success && "Registration should succeed for auth test");

    // Test successful login
    auto loginResult = auth.authenticateUser("testuser2", "password123");
    assert(loginResult.success && "Login should succeed");
    assert(loginResult.userId == regResult.userId && "User ID should match");
    assert(loginResult.username == "testuser2" && "Username should match");
    assert(!loginResult.token.empty() && "Token should not be empty");
    assert(!loginResult.sessionId.empty() && "Session ID should not be empty");
    std::cout << "✓ Login successful" << std::endl;

    // Test wrong password
    auto wrongPassResult = auth.authenticateUser("testuser2", "wrongpassword");
    assert(!wrongPassResult.success && "Wrong password should fail");
    std::cout << "✓ Wrong password rejected" << std::endl;

    // Test non-existent user
    auto nonexistentResult = auth.authenticateUser("nonexistent", "password123");
    assert(!nonexistentResult.success && "Non-existent user should fail");
    std::cout << "✓ Non-existent user rejected" << std::endl;

    // Test authentication state
    assert(auth.isUserLoggedIn() && "User should be logged in");
    assert(auth.getCurrentUsername() == "testuser2" && "Current username should match");
    assert(auth.getCurrentUserId() == regResult.userId && "Current user ID should match");
    std::cout << "✓ Authentication state correct" << std::endl;
}

void testTokenManagement(DegenHF::ECCAuthHandler& auth) {
    std::cout << "Testing token management..." << std::endl;

    // Login to get a token
    auto loginResult = auth.authenticateUser("testuser2", "password123");
    assert(loginResult.success && "Login should succeed for token test");

    // Test token verification
    auto tokenOpt = auth.verifyToken(loginResult.token);
    assert(tokenOpt.has_value() && "Token should be valid");
    assert(tokenOpt->userId == loginResult.userId && "Token user ID should match");
    assert(tokenOpt->username == loginResult.username && "Token username should match");
    std::cout << "✓ Token verification successful" << std::endl;

    // Test invalid token
    auto invalidTokenOpt = auth.verifyToken("invalid.token.here");
    assert(!invalidTokenOpt.has_value() && "Invalid token should fail verification");
    std::cout << "✓ Invalid token rejected" << std::endl;

    // Test token invalidation
    bool invalidated = auth.invalidateToken(tokenOpt->tokenId);
    assert(invalidated && "Token invalidation should succeed");

    auto invalidatedTokenOpt = auth.verifyToken(loginResult.token);
    assert(!invalidatedTokenOpt.has_value() && "Invalidated token should fail verification");
    std::cout << "✓ Token invalidation works" << std::endl;
}

void testSessionManagement(DegenHF::ECCAuthHandler& auth) {
    std::cout << "Testing session management..." << std::endl;

    // Login to create a session
    auto loginResult = auth.authenticateUser("testuser2", "password123");
    assert(loginResult.success && "Login should succeed for session test");

    // Test session retrieval
    auto sessionOpt = auth.getSession(loginResult.sessionId);
    assert(sessionOpt.has_value() && "Session should exist");
    assert(sessionOpt->userId == loginResult.userId && "Session user ID should match");
    assert(sessionOpt->username == loginResult.username && "Session username should match");
    assert(sessionOpt->isActive && "Session should be active");
    std::cout << "✓ Session retrieval successful" << std::endl;

    // Test invalid session
    auto invalidSessionOpt = auth.getSession("invalid-session-id");
    assert(!invalidSessionOpt.has_value() && "Invalid session should not exist");
    std::cout << "✓ Invalid session rejected" << std::endl;

    // Test session invalidation
    bool invalidated = auth.invalidateSession(loginResult.sessionId);
    assert(invalidated && "Session invalidation should succeed");

    auto invalidatedSessionOpt = auth.getSession(loginResult.sessionId);
    assert(!invalidatedSessionOpt.has_value() && "Invalidated session should not exist");
    std::cout << "✓ Session invalidation works" << std::endl;
}

void testDataPersistence(DegenHF::ECCAuthHandler& auth) {
    std::cout << "Testing data persistence..." << std::endl;

    // Register a new user
    auto regResult = auth.registerUser("persistuser", "persistpass123");
    assert(regResult.success && "Registration should succeed for persistence test");

    // Save data
    bool saved = auth.saveAuthData();
    assert(saved && "Data saving should succeed");
    std::cout << "✓ Data saving successful" << std::endl;

    // Create new auth handler instance
    DegenHF::AuthConfig config;
    config.userDataPath = "test_auth_data";
    DegenHF::ECCAuthHandler newAuth(config);
    assert(newAuth.initialize() && "New auth handler should initialize");

    // Load data
    bool loaded = newAuth.loadAuthData();
    assert(loaded && "Data loading should succeed");

    // Try to authenticate with loaded data
    auto loginResult = newAuth.authenticateUser("persistuser", "persistpass123");
    assert(loginResult.success && "Authentication with loaded data should succeed");
    std::cout << "✓ Data persistence works" << std::endl;
}

void testLogout(DegenHF::ECCAuthHandler& auth) {
    std::cout << "Testing logout functionality..." << std::endl;

    // Login first
    auto loginResult = auth.authenticateUser("testuser2", "password123");
    assert(loginResult.success && "Login should succeed for logout test");
    assert(auth.isUserLoggedIn() && "User should be logged in before logout");

    // Logout
    auth.logout();

    // Verify logout
    assert(!auth.isUserLoggedIn() && "User should not be logged in after logout");
    assert(auth.getCurrentUsername().empty() && "Current username should be empty after logout");
    assert(auth.getCurrentUserId().empty() && "Current user ID should be empty after logout");
    std::cout << "✓ Logout functionality works" << std::endl;
}

void testConcurrentAccess() {
    std::cout << "Testing concurrent access..." << std::endl;

    DegenHF::AuthConfig config;
    config.userDataPath = "concurrent_test_data";

    // Test multiple auth handlers
    DegenHF::ECCAuthHandler auth1(config);
    DegenHF::ECCAuthHandler auth2(config);

    assert(auth1.initialize() && "First auth handler should initialize");
    assert(auth2.initialize() && "Second auth handler should initialize");

    // Register with first handler
    auto regResult = auth1.registerUser("concurrent_user", "concurrent_pass");
    assert(regResult.success && "Registration should succeed");

    // Authenticate with second handler
    auto loginResult = auth2.authenticateUser("concurrent_user", "concurrent_pass");
    assert(loginResult.success && "Concurrent authentication should succeed");

    std::cout << "✓ Concurrent access works" << std::endl;
}

void runAllTests() {
    std::cout << "Running DegenHF ECC Authentication Tests" << std::endl;
    std::cout << "=========================================" << std::endl;

    // Create test auth handler
    DegenHF::AuthConfig config;
    config.hashIterations = 1000; // Faster for testing
    config.tokenExpiryHours = 1;
    config.userDataPath = "test_auth_data";

    DegenHF::ECCAuthHandler auth(config);

    if (!auth.initialize()) {
        std::cerr << "Failed to initialize auth handler for tests" << std::endl;
        return;
    }

    try {
        testUserRegistration(auth);
        testUserAuthentication(auth);
        testTokenManagement(auth);
        testSessionManagement(auth);
        testDataPersistence(auth);
        testLogout(auth);
        testConcurrentAccess();

        std::cout << std::endl << "All tests passed! ✓" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    runAllTests();
    return 0;
}