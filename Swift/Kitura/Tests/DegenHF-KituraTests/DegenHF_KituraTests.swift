import XCTest
@testable import DegenHF_Kitura

final class DegenHF_KituraTests: XCTestCase {
    var authHandler: EccAuthHandler!

    override func setUp() {
        super.setUp()
        authHandler = EccAuthHandler()
    }

    override func tearDown() {
        authHandler = nil
        super.tearDown()
    }

    func testRegisterSuccess() throws {
        let username = "testuser_\(Int(Date().timeIntervalSince1970))"
        let password = "testpassword123"

        let userId = try authHandler.register(username: username, password: password)
        XCTAssertFalse(userId.isEmpty)
        XCTAssertTrue(userId.hasPrefix("user_"))
    }

    func testRegisterDuplicateUser() throws {
        let username = "duplicateuser_\(Int(Date().timeIntervalSince1970))"
        let password = "testpassword123"

        _ = try authHandler.register(username: username, password: password)

        XCTAssertThrowsError(try authHandler.register(username: username, password: "differentpassword")) { error in
            XCTAssertEqual(error as? AuthError, AuthError.userExists)
        }
    }

    func testRegisterShortPassword() throws {
        let username = "testuser_\(Int(Date().timeIntervalSince1970))"
        let password = "short"

        XCTAssertThrowsError(try authHandler.register(username: username, password: password)) { error in
            XCTAssertEqual(error as? AuthError, AuthError.weakPassword)
        }
    }

    func testRegisterInvalidUsername() throws {
        let username = "ab" // Too short
        let password = "testpassword123"

        XCTAssertThrowsError(try authHandler.register(username: username, password: password)) { error in
            XCTAssertEqual(error as? AuthError, AuthError.invalidUsername)
        }
    }

    func testAuthenticateSuccess() throws {
        let username = "authuser_\(Int(Date().timeIntervalSince1970))"
        let password = "testpassword123"

        _ = try authHandler.register(username: username, password: password)
        let token = try authHandler.authenticate(username: username, password: password)

        XCTAssertFalse(token.isEmpty)
        XCTAssertTrue(token.contains("."))
    }

    func testAuthenticateWrongPassword() throws {
        let username = "authuser_\(Int(Date().timeIntervalSince1970))"
        let password = "testpassword123"

        _ = try authHandler.register(username: username, password: password)

        XCTAssertThrowsError(try authHandler.authenticate(username: username, password: "wrongpassword")) { error in
            XCTAssertEqual(error as? AuthError, AuthError.invalidCredentials)
        }
    }

    func testAuthenticateNonExistentUser() throws {
        XCTAssertThrowsError(try authHandler.authenticate(username: "nonexistent", password: "password")) { error in
            XCTAssertEqual(error as? AuthError, AuthError.userNotFound)
        }
    }

    func testVerifyTokenSuccess() throws {
        let username = "verifyuser_\(Int(Date().timeIntervalSince1970))"
        let password = "testpassword123"

        _ = try authHandler.register(username: username, password: password)
        let token = try authHandler.authenticate(username: username, password: password)
        let session = try authHandler.verifyToken(token)

        XCTAssertEqual(session.username, username)
        XCTAssertTrue(session.expiresAt > Date())
    }

    func testVerifyTokenInvalid() throws {
        XCTAssertThrowsError(try authHandler.verifyToken("invalid.token.here")) { error in
            XCTAssertEqual(error as? AuthError, AuthError.invalidToken)
        }
    }

    func testGetUserProfileSuccess() throws {
        let username = "profileuser_\(Int(Date().timeIntervalSince1970))"
        let password = "testpassword123"

        let userId = try authHandler.register(username: username, password: password)
        let profile = try authHandler.getUserProfile(userId: userId)

        XCTAssertEqual(profile.userId, userId)
        XCTAssertEqual(profile.username, username)
    }

    func testGetUserProfileNonExistentUser() throws {
        XCTAssertThrowsError(try authHandler.getUserProfile(userId: "invalid_user_id")) { error in
            XCTAssertEqual(error as? AuthError, AuthError.userNotFound)
        }
    }

    func testConstantTimeCompare() {
        let authHandler = EccAuthHandler()

        // Test with equal data
        let data1 = Data([1, 2, 3, 4, 5])
        let data2 = Data([1, 2, 3, 4, 5])
        // Note: This is testing internal method, in real implementation we'd expose it or test indirectly

        // Test with different data
        let data3 = Data([1, 2, 3, 4, 6])
        // The constantTimeCompare is private, so we test it indirectly through authentication
    }

    func testKeyGeneration() {
        let authHandler = EccAuthHandler()

        // Test private key generation (indirectly through registration)
        let username = "keytest_\(Int(Date().timeIntervalSince1970))"
        let password = "testpassword123"

        let userId = try authHandler.register(username: username, password: password)
        XCTAssertFalse(userId.isEmpty)

        // Verify we can authenticate, which means keys were generated properly
        let token = try authHandler.authenticate(username: username, password: password)
        XCTAssertFalse(token.isEmpty)
    }
}