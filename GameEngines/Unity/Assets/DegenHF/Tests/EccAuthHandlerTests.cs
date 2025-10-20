using UnityEngine;
using UnityEngine.TestTools;
using NUnit.Framework;
using DegenHF.EccAuth.Unity;
using System.Threading.Tasks;

namespace DegenHF.EccAuth.Unity.Tests
{
    public class EccAuthHandlerTests
    {
        private GameObject _testObject;
        private EccAuthHandler _authHandler;

        [SetUp]
        public void Setup()
        {
            _testObject = new GameObject("TestAuth");
            _authHandler = _testObject.AddComponent<EccAuthHandler>();
            _authHandler.Initialize();
        }

        [TearDown]
        public void Teardown()
        {
            Object.Destroy(_testObject);
            PlayerPrefs.DeleteAll();
        }

        [Test]
        public async Task RegisterAsync_ValidCredentials_ReturnsUserId()
        {
            // Arrange
            var username = "testuser";
            var password = "testpass123";

            // Act
            var userId = await _authHandler.RegisterAsync(username, password);

            // Assert
            Assert.IsNotNull(userId);
            Assert.IsTrue(userId.StartsWith("user_"));
        }

        [Test]
        public void RegisterAsync_EmptyUsername_ThrowsException()
        {
            // Arrange
            var username = "";
            var password = "testpass123";

            // Act & Assert
            Assert.ThrowsAsync<System.ArgumentException>(async () =>
                await _authHandler.RegisterAsync(username, password));
        }

        [Test]
        public async Task AuthenticateAsync_ValidCredentials_ReturnsToken()
        {
            // Arrange
            var username = "testuser";
            var password = "testpass123";

            // Register first
            var userId = await _authHandler.RegisterAsync(username, password);

            // Act
            var token = await _authHandler.AuthenticateAsync(username, password);

            // Assert
            Assert.IsNotNull(token);
            Assert.IsTrue(token.Contains("."));
        }

        [Test]
        public async Task VerifyToken_ValidToken_ReturnsClaims()
        {
            // Arrange
            var username = "testuser";
            var password = "testpass123";

            // Register and authenticate
            await _authHandler.RegisterAsync(username, password);
            var token = await _authHandler.AuthenticateAsync(username, password);

            // Act
            var claims = _authHandler.VerifyToken(token);

            // Assert
            Assert.IsNotNull(claims);
            Assert.AreEqual(username, claims.Username);
        }

        [Test]
        public void CreateSession_ValidUserId_ReturnsSessionId()
        {
            // Arrange
            var userId = "test_user_123";

            // Act
            var sessionId = _authHandler.CreateSession(userId);

            // Assert
            Assert.IsNotNull(sessionId);
            Assert.IsTrue(sessionId.StartsWith("session_"));
        }

        [Test]
        public void GetSession_ValidSessionId_ReturnsSession()
        {
            // Arrange
            var userId = "test_user_123";
            var sessionId = _authHandler.CreateSession(userId);

            // Act
            var session = _authHandler.GetSession(sessionId);

            // Assert
            Assert.IsNotNull(session);
            Assert.AreEqual(userId, session.UserId);
        }

        [Test]
        public async Task PasswordHashing_ConsistentResults()
        {
            // Arrange
            var password = "testpassword123";

            // Act
            var hash1 = await GetHashForPassword(_authHandler, password);
            var hash2 = await GetHashForPassword(_authHandler, password);

            // Assert - Hashes should be different due to random salt
            Assert.AreNotEqual(hash1, hash2);
        }

        // Helper method to access private hash method for testing
        private async Task<string> GetHashForPassword(EccAuthHandler handler, string password)
        {
            // This would require reflection in a real test
            // For demo purposes, we'll test the public API
            var userId = await handler.RegisterAsync("tempuser", password);
            return PlayerPrefs.GetString($"user_{userId}_hash");
        }
    }
}