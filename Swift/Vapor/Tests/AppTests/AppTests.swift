import XCTest
import Vapor
@testable import App

final class AppTests: XCTestCase {
    var app: Application!
    var authHandler: EccAuthHandler!

    override func setUp() async throws {
        app = try await Application.make(.testing)
        try configure(app)

        authHandler = app.storage.get(EccAuthHandlerKey.self)!
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        app = nil
    }

    func testUserRegistrationAndAuthentication() throws {
        let username = "testuser"
        let password = "testpassword123"

        // Register user
        let userId = try authHandler.register(username: username, password: password)
        XCTAssertFalse(userId.isEmpty)
        XCTAssertTrue(userId.hasPrefix("user_"))

        // Authenticate user
        let token = try authHandler.authenticate(username: username, password: password)
        XCTAssertFalse(token.isEmpty)

        // Verify token
        let session = try authHandler.verifyToken(token)
        XCTAssertEqual(userId, session.userId)
        XCTAssertEqual(username, session.username)
    }

    func testInvalidCredentials() throws {
        let username = "testuser"
        let password = "testpassword123"

        // Register user
        try authHandler.register(username: username, password: password)

        // Try to authenticate with wrong password
        XCTAssertThrowsError(try authHandler.authenticate(username: username, password: "wrongpassword")) { error in
            XCTAssertTrue(error is AuthError)
        }

        // Try to authenticate non-existent user
        XCTAssertThrowsError(try authHandler.authenticate(username: "nonexistent", password: password)) { error in
            XCTAssertTrue(error is AuthError)
        }
    }

    func testDuplicateUserRegistration() throws {
        let username = "testuser"
        let password = "testpassword123"

        // Register user first time
        try authHandler.register(username: username, password: password)

        // Try to register same user again
        XCTAssertThrowsError(try authHandler.register(username: username, password: "differentpassword")) { error in
            XCTAssertTrue(error is AuthError)
        }
    }

    func testInvalidRegistrationInput() throws {
        // Empty username
        XCTAssertThrowsError(try authHandler.register(username: "", password: "password123")) { error in
            XCTAssertTrue(error is AuthError)
        }

        // Short password
        XCTAssertThrowsError(try authHandler.register(username: "username", password: "short")) { error in
            XCTAssertTrue(error is AuthError)
        }
    }

    func testUserProfileRetrieval() throws {
        let username = "testuser"
        let password = "testpassword123"

        // Register and authenticate user
        let userId = try authHandler.register(username: username, password: password)
        let token = try authHandler.authenticate(username: username, password: password)
        let session = try authHandler.verifyToken(token)

        // Get user profile
        let profile = try authHandler.getUserProfile(userId: userId)
        XCTAssertEqual(userId, profile.userId)
        XCTAssertEqual(username, profile.username)
    }

    func testSessionManagement() throws {
        let username = "testuser"
        let password = "testpassword123"

        // Register user
        let userId = try authHandler.register(username: username, password: password)

        // Create session
        let session = try authHandler.createSession(userId: userId)
        XCTAssertEqual(userId, session.userId)
        XCTAssertEqual(username, session.username)

        // Get session
        let retrievedSession = authHandler.getSession(sessionId: session.sessionId)
        XCTAssertNotNil(retrievedSession)
        XCTAssertEqual(session.sessionId, retrievedSession?.sessionId)
    }

    func testTokenVerificationCaching() throws {
        let username = "testuser"
        let password = "testpassword123"

        // Register and authenticate user
        try authHandler.register(username: username, password: password)
        let token = try authHandler.authenticate(username: username, password: password)

        // First verification
        let session1 = try authHandler.verifyToken(token)
        XCTAssertNotNil(session1)

        // Second verification (should use cache)
        let session2 = try authHandler.verifyToken(token)
        XCTAssertNotNil(session2)
        XCTAssertEqual(session1.sessionId, session2.sessionId)
    }

    // MARK: - Integration Tests

    func testHealthEndpoint() async throws {
        try await app.test(.GET, "health") { res async in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode([String: Any].self)
            XCTAssertEqual(body["status"] as? String, "healthy")
            XCTAssertEqual(body["service"] as? String, "degenhf-vapor")
        }
    }

    func testRegisterEndpoint() async throws {
        let registerData = RegisterRequest(username: "testuser", password: "testpassword123")

        try await app.test(.POST, "api/auth/register", content: registerData) { res async in
            XCTAssertEqual(res.status, .created)
            let body = try res.content.decode([String: String].self)
            XCTAssertNotNil(body["user_id"])
            XCTAssertEqual(body["message"], "User registered successfully")
        }
    }

    func testLoginEndpoint() async throws {
        // First register a user
        let registerData = RegisterRequest(username: "testuser", password: "testpassword123")
        try await app.test(.POST, "api/auth/register", content: registerData) { res async in
            XCTAssertEqual(res.status, .created)
        }

        // Then login
        let loginData = LoginRequest(username: "testuser", password: "testpassword123")
        try await app.test(.POST, "api/auth/login", content: loginData) { res async in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode([String: String].self)
            XCTAssertNotNil(body["token"])
            XCTAssertEqual(body["message"], "Login successful")
        }
    }

    func testProtectedEndpointWithoutToken() async throws {
        try await app.test(.GET, "api/protected") { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    func testProtectedEndpointWithValidToken() async throws {
        // Register and login to get token
        let registerData = RegisterRequest(username: "testuser", password: "testpassword123")
        try await app.test(.POST, "api/auth/register", content: registerData)

        let loginData = LoginRequest(username: "testuser", password: "testpassword123")
        var token = ""
        try await app.test(.POST, "api/auth/login", content: loginData) { res async in
            let body = try res.content.decode([String: String].self)
            token = body["token"]!
        }

        // Access protected endpoint with token
        try await app.test(.GET, "api/protected", headers: ["Authorization": "Bearer \(token)"]) { res async in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode([String: Any].self)
            XCTAssertTrue((body["message"] as! String).contains("Welcome"))
        }
    }
}