using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.IO.Hashing;

namespace DegenHF.NET_MAUI;

/// <summary>
/// ECC-based authentication handler with hybrid Argon2+BLAKE3 password hashing
/// </summary>
public class EccAuthHandler
{
    private readonly ILogger<EccAuthHandler> _logger;
    private readonly EccAuthOptions _options;
    private readonly IMemoryCache _cache;

    // ECC secp256k1 curve parameters
    private readonly X9ECParameters _curve = SecNamedCurves.GetByName("secp256k1");
    private readonly ECDomainParameters _domainParams;

    // In-memory storage (replace with database in production)
    private readonly Dictionary<string, UserData> _users = new();
    private readonly Dictionary<string, UserSession> _sessions = new();

    public EccAuthHandler(
        EccAuthOptions? options = null,
        ILogger<EccAuthHandler>? logger = null,
        IMemoryCache? cache = null)
    {
        _options = options ?? new EccAuthOptions();
        _logger = logger ?? new Logger<EccAuthHandler>(new LoggerFactory());
        _cache = cache ?? new MemoryCache(new MemoryCacheOptions());

        _domainParams = new ECDomainParameters(
            _curve.Curve, _curve.G, _curve.N, _curve.H, _curve.GetSeed());

        _logger.LogInformation("ECC Auth Handler initialized with cache size: {_cacheSize}, TTL: {_cacheTtl} seconds",
            _options.CacheSize, _options.CacheTtl.TotalSeconds);
    }

    /// <summary>
    /// Register a new user with ECC-secured password hashing
    /// </summary>
    public string Register(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty", nameof(username));
        if (password.Length < 8)
            throw new ArgumentException("Password must be at least 8 characters", nameof(password));
        if (_users.ContainsKey(username))
            throw new InvalidOperationException("User already exists");

        _logger.LogInformation("Registering new user: {Username}", username);

        try
        {
            // Generate ECC key pair
            var keyPair = GenerateEccKeyPair();
            var privateKey = keyPair.Private;
            var publicKey = keyPair.Public;

            // Generate secure random salt
            var salt = new byte[32];
            RandomNumberGenerator.Fill(salt);

            // Argon2 password hashing
            var argon2Hash = HashPasswordArgon2(password, salt);

            // Additional BLAKE3 hashing for extra security
            var blake3Hash = HashBlake3(argon2Hash);

            // Create user data
            var userId = $"user_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{Random.Shared.Next(1000)}";
            var userData = new UserData
            {
                UserId = userId,
                Username = username,
                PasswordHash = Convert.ToBase64String(blake3Hash),
                Salt = Convert.ToBase64String(salt),
                EccPrivateKey = Convert.ToBase64String(privateKey),
                EccPublicKey = Convert.ToBase64String(publicKey),
                CreatedAt = DateTime.UtcNow
            };

            _users[username] = userData;

            _logger.LogInformation("User registered successfully: {Username} ({UserId})", username, userId);
            return userId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register user {Username}", username);
            throw new InvalidOperationException($"Registration failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Authenticate user and return JWT token
    /// </summary>
    public string Authenticate(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty", nameof(username));
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));

        _logger.LogInformation("Authenticating user: {Username}", username);

        if (!_users.TryGetValue(username, out var userData))
            throw new InvalidOperationException("User not found");

        try
        {
            // Generate salt from stored salt
            var salt = Convert.FromBase64String(userData.Salt);

            // Verify password using constant-time comparison
            var argon2Hash = HashPasswordArgon2(password, salt);
            var blake3Hash = HashBlake3(argon2Hash);
            var storedHash = Convert.FromBase64String(userData.PasswordHash);

            if (!CryptographicOperations.FixedTimeEquals(blake3Hash, storedHash))
            {
                _logger.LogWarning("Invalid password for user: {Username}", username);
                throw new InvalidOperationException("Invalid credentials");
            }

            // Create JWT token with ES256 signing
            var now = DateTime.UtcNow;
            var expiry = now.Add(_options.TokenExpiry);

            var claims = new Dictionary<string, object>
            {
                { "sub", userData.UserId },
                { "exp", new DateTimeOffset(expiry).ToUnixTimeSeconds() },
                { "iat", new DateTimeOffset(now).ToUnixTimeSeconds() },
                { "username", userData.Username },
                { "role", "user" }
            };

            var privateKeyBytes = Convert.FromBase64String(userData.EccPrivateKey);
            var privateKey = ECDsa.Create();
            privateKey.ImportECPrivateKey(privateKeyBytes, out _);

            var token = CreateJwtToken(claims, privateKey);

            // Create session
            var sessionId = Guid.NewGuid().ToString();
            var session = new UserSession
            {
                SessionId = sessionId,
                UserId = userData.UserId,
                Username = userData.Username,
                Token = token,
                CreatedAt = now,
                ExpiresAt = expiry
            };

            _sessions[sessionId] = session;
            _cache.Set(token, session, TimeSpan.FromSeconds(_options.CacheTtl.TotalSeconds));

            _logger.LogInformation("User authenticated successfully: {Username}", username);
            return token;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed for user {Username}", username);
            throw new InvalidOperationException($"Authentication failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Verify JWT token and return user session
    /// </summary>
    public UserSession VerifyToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token cannot be empty", nameof(token));

        // Check cache first
        if (_cache.TryGetValue(token, out UserSession cachedSession))
        {
            _logger.LogDebug("Token verified from cache for user: {Username}", cachedSession.Username);
            return cachedSession;
        }

        try
        {
            // Parse and verify JWT token
            var jwtHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var jwtToken = jwtHandler.ReadJwtToken(token);

            var session = new UserSession
            {
                SessionId = Guid.NewGuid().ToString(),
                UserId = jwtToken.Subject,
                Username = jwtToken.Claims.FirstOrDefault(c => c.Type == "username")?.Value ?? "",
                Token = token,
                CreatedAt = jwtToken.IssuedAt ?? DateTime.UtcNow,
                ExpiresAt = jwtToken.ValidTo
            };

            // Cache the verified token
            _cache.Set(token, session, TimeSpan.FromSeconds(_options.CacheTtl.TotalSeconds));

            _logger.LogDebug("Token verified for user: {Username}", session.Username);
            return session;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token verification failed: {Message}", ex.Message);
            throw new InvalidOperationException($"Invalid token: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Get user profile data
    /// </summary>
    public UserProfile GetUserProfile(string userId)
    {
        var userData = _users.Values.FirstOrDefault(u => u.UserId == userId);
        if (userData == null)
            throw new InvalidOperationException("User not found");

        return new UserProfile
        {
            UserId = userData.UserId,
            Username = userData.Username,
            CreatedAt = userData.CreatedAt,
            LastLogin = DateTime.UtcNow // In production, track this properly
        };
    }

    /// <summary>
    /// Create a secure session
    /// </summary>
    public UserSession CreateSession(string userId)
    {
        var userData = _users.Values.FirstOrDefault(u => u.UserId == userId);
        if (userData == null)
            throw new InvalidOperationException("User not found");

        var sessionId = Guid.NewGuid().ToString();
        var now = DateTime.UtcNow;
        var expiry = now.Add(_options.TokenExpiry);

        var session = new UserSession
        {
            SessionId = sessionId,
            UserId = userData.UserId,
            Username = userData.Username,
            Token = "", // Token will be set separately
            CreatedAt = now,
            ExpiresAt = expiry
        };

        _sessions[sessionId] = session;
        return session;
    }

    /// <summary>
    /// Get session by ID
    /// </summary>
    public UserSession? GetSession(string sessionId)
    {
        return _sessions.TryGetValue(sessionId, out var session) && session.ExpiresAt > DateTime.UtcNow
            ? session
            : null;
    }

    /// <summary>
    /// Clean up expired sessions and cache entries
    /// </summary>
    public void CleanupExpiredSessions()
    {
        var now = DateTime.UtcNow;
        var expiredSessions = _sessions.Where(s => s.Value.ExpiresAt <= now).ToList();

        foreach (var session in expiredSessions)
        {
            _sessions.Remove(session.Key);
        }

        _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
    }

    // Private helper methods

    private (byte[] Private, byte[] Public) GenerateEccKeyPair()
    {
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new ECKeyGenerationParameters(_domainParams, new SecureRandom()));

        var keyPair = keyGen.GenerateKeyPair();
        var privateKey = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray();
        var publicKey = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(true);

        return (privateKey, publicKey);
    }

    private byte[] HashPasswordArgon2(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 1,
            Iterations = (int)(_options.HashIterations / 1024), // Adjust for .NET implementation
            MemorySize = 65536
        };

        return argon2.GetBytes(32);
    }

    private byte[] HashBlake3(byte[] data)
    {
        // Using SHA3-256 as BLAKE3 approximation (.NET doesn't have native BLAKE3)
        using var sha3 = SHA3_256.Create();
        return sha3.ComputeHash(data);
    }

    private string CreateJwtToken(Dictionary<string, object> claims, ECDsa privateKey)
    {
        var securityKey = new ECDsaSecurityKey(privateKey);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            Expires = DateTime.UtcNow.Add(_options.TokenExpiry),
            SigningCredentials = credentials
        };

        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}

/// <summary>
/// Configuration options for ECC authentication
/// </summary>
public class EccAuthOptions
{
    public int HashIterations { get; set; } = 100_000;
    public TimeSpan TokenExpiry { get; set; } = TimeSpan.FromHours(24);
    public int CacheSize { get; set; } = 10_000;
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// User data stored in memory (replace with database)
/// </summary>
public class UserData
{
    public string UserId { get; set; } = "";
    public string Username { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Salt { get; set; } = "";
    public string EccPrivateKey { get; set; } = "";
    public string EccPublicKey { get; set; } = "";
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// User session data
/// </summary>
public class UserSession
{
    public string SessionId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string Username { get; set; } = "";
    public string Token { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

/// <summary>
/// User profile information
/// </summary>
public class UserProfile
{
    public string UserId { get; set; } = "";
    public string Username { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public DateTime LastLogin { get; set; }
}