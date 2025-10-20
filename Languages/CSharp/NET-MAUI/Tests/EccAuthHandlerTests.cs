using System;
using System.Linq;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Xunit;

namespace DegenHF.NET_MAUI.Tests;

public class EccAuthHandlerTests
{
    private readonly EccAuthHandler _authHandler;
    private readonly ILogger<EccAuthHandler> _logger;
    private readonly IMemoryCache _cache;

    public EccAuthHandlerTests()
    {
        var options = new EccAuthOptions
        {
            HashIterations = 1000, // Lower for faster tests
            TokenExpiry = TimeSpan.FromMinutes(5),
            CacheSize = 100,
            CacheTtl = TimeSpan.FromSeconds(30)
        };

        _logger = new Logger<EccAuthHandler>(new LoggerFactory());
        _cache = new MemoryCache(new MemoryCacheOptions());
        _authHandler = new EccAuthHandler(options, _logger, _cache);
    }

    [Fact]
    public void Register_ValidInput_ReturnsUserId()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";

        // Act
        var userId = _authHandler.Register(username, password);

        // Assert
        Assert.NotNull(userId);
        Assert.StartsWith("user_", userId);
    }

    [Fact]
    public void Register_EmptyUsername_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _authHandler.Register("", "password123"));
        Assert.Equal("Username cannot be empty", exception.Message);
    }

    [Fact]
    public void Register_ShortPassword_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _authHandler.Register("username", "short"));
        Assert.Equal("Password must be at least 8 characters", exception.Message);
    }

    [Fact]
    public void Register_DuplicateUser_ThrowsInvalidOperationException()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";
        _authHandler.Register(username, password);

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => _authHandler.Register(username, "differentpassword"));
        Assert.Equal("User already exists", exception.Message);
    }

    [Fact]
    public void Authenticate_ValidCredentials_ReturnsToken()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";
        _authHandler.Register(username, password);

        // Act
        var token = _authHandler.Authenticate(username, password);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public void Authenticate_InvalidCredentials_ThrowsInvalidOperationException()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";
        _authHandler.Register(username, password);

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => _authHandler.Authenticate(username, "wrongpassword"));
        Assert.Equal("Invalid credentials", exception.Message);
    }

    [Fact]
    public void Authenticate_NonExistentUser_ThrowsInvalidOperationException()
    {
        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => _authHandler.Authenticate("nonexistent", "password123"));
        Assert.Equal("User not found", exception.Message);
    }

    [Fact]
    public void VerifyToken_ValidToken_ReturnsSession()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";
        _authHandler.Register(username, password);
        var token = _authHandler.Authenticate(username, password);

        // Act
        var session = _authHandler.VerifyToken(token);

        // Assert
        Assert.NotNull(session);
        Assert.Equal(username, session.Username);
    }

    [Fact]
    public void VerifyToken_EmptyToken_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _authHandler.VerifyToken(""));
        Assert.Equal("Token cannot be empty", exception.Message);
    }

    [Fact]
    public void GetUserProfile_ValidUserId_ReturnsProfile()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";
        _authHandler.Register(username, password);
        var token = _authHandler.Authenticate(username, password);
        var session = _authHandler.VerifyToken(token);

        // Act
        var profile = _authHandler.GetUserProfile(session.UserId);

        // Assert
        Assert.NotNull(profile);
        Assert.Equal(session.UserId, profile.UserId);
        Assert.Equal(username, profile.Username);
    }

    [Fact]
    public void GetUserProfile_NonExistentUser_ThrowsInvalidOperationException()
    {
        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => _authHandler.GetUserProfile("nonexistent"));
        Assert.Equal("User not found", exception.Message);
    }

    [Fact]
    public void CreateSession_ValidUserId_ReturnsSession()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";
        _authHandler.Register(username, password);
        var token = _authHandler.Authenticate(username, password);
        var session = _authHandler.VerifyToken(token);

        // Act
        var newSession = _authHandler.CreateSession(session.UserId);

        // Assert
        Assert.NotNull(newSession);
        Assert.Equal(session.UserId, newSession.UserId);
        Assert.Equal(username, newSession.Username);
    }

    [Fact]
    public void GetSession_ValidSessionId_ReturnsSession()
    {
        // Arrange
        var username = "testuser";
        var password = "testpassword123";
        _authHandler.Register(username, password);
        var token = _authHandler.Authenticate(username, password);
        var session = _authHandler.VerifyToken(token);
        var createdSession = _authHandler.CreateSession(session.UserId);

        // Act
        var retrievedSession = _authHandler.GetSession(createdSession.SessionId);

        // Assert
        Assert.NotNull(retrievedSession);
        Assert.Equal(createdSession.SessionId, retrievedSession.SessionId);
    }

    [Fact]
    public void GetSession_NonExistentSessionId_ReturnsNull()
    {
        // Act
        var session = _authHandler.GetSession("nonexistent");

        // Assert
        Assert.Null(session);
    }
}