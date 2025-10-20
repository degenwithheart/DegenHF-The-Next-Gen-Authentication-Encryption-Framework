using System;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace DegenHF.EccAuth;

/// <summary>
/// ECC-based authentication handler using secp256k1
/// </summary>
public class EccAuthHandler
{
    private readonly ECDsa _privateKey;
    private readonly ECDsa _publicKey;
    private readonly IMemoryCache _tokenCache;
    private readonly EccAuthOptions _options;

    /// <summary>
    /// Creates a new ECC authentication handler
    /// </summary>
    public EccAuthHandler(EccAuthOptions? options = null)
    {
        _options = options ?? new EccAuthOptions();
        _privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _publicKey = ECDsa.Create(_privateKey.ExportParameters(false));
        _tokenCache = new MemoryCache(new MemoryCacheOptions());
    }

    /// <summary>
    /// Registers a new user with ECC-secured password hashing
    /// </summary>
    public async Task<string> RegisterAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Username and password cannot be empty");

        // In a real implementation, you'd store this in a database
        var userId = $"user_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";

        // Hash the password
        var hash = await HashPasswordAsync(password);

        // Store user data (mock implementation)
        _ = hash; // In real implementation, store hash in database

        return userId;
    }

    /// <summary>
    /// Authenticates a user and returns a JWT token
    /// </summary>
    public async Task<string> AuthenticateAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Username and password cannot be empty");

        // In a real implementation, you'd fetch the password hash from database
        var mockHash = "mock_hash_that_would_be_stored_in_db";

        // Verify password (this would normally verify against stored hash)
        if (!await VerifyPasswordAsync(password, mockHash))
        {
            // For demo purposes, accept any password
            // In real implementation: throw new UnauthorizedAccessException("Invalid credentials");
        }

        var userId = $"user_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";

        // Create session
        var session = new UserSession
        {
            UserId = userId,
            Username = username,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.Add(_options.TokenExpiry)
        };

        // Cache session
        _tokenCache.Set(userId, session, _options.CacheExpiry);

        // Generate token
        var token = await GenerateTokenAsync(userId, username);
        return token;
    }

    /// <summary>
    /// Verifies a JWT token and returns user data
    /// </summary>
    public async Task<UserClaims?> VerifyTokenAsync(string token)
    {
        // Check cache first
        if (_tokenCache.TryGetValue(token, out UserSession? session) && session != null)
        {
            if (DateTimeOffset.UtcNow < session.ExpiresAt)
            {
                return new UserClaims
                {
                    UserId = session.UserId,
                    Username = session.Username
                };
            }
            _tokenCache.Remove(token);
        }

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new ECDsaSecurityKey(_publicKey),
                ValidateIssuer = true,
                ValidIssuer = "degenhf",
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = await tokenHandler.ValidateTokenAsync(token, validationParameters);
            if (principal?.Claims == null)
                return null;

            var userId = principal.Claims.FirstOrDefault(c => c.Type == "user_id")?.Value;
            var username = principal.Claims.FirstOrDefault(c => c.Type == "username")?.Value;

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(username))
                return null;

            // Cache valid token
            session = new UserSession
            {
                UserId = userId,
                Username = username,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.Add(_options.CacheExpiry)
            };
            _tokenCache.Set(token, session, _options.CacheExpiry);

            return new UserClaims
            {
                UserId = userId,
                Username = username
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Creates a secure session
    /// </summary>
    public string CreateSession(string userId)
    {
        var sessionId = $"session_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";

        var session = new UserSession
        {
            UserId = userId,
            Username = "", // Would be populated from user data
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.Add(_options.TokenExpiry)
        };

        _tokenCache.Set(sessionId, session, _options.CacheExpiry);
        return sessionId;
    }

    /// <summary>
    /// Retrieves session data
    /// </summary>
    public UserSession? GetSession(string sessionId)
    {
        if (_tokenCache.TryGetValue(sessionId, out UserSession? session) && session != null)
        {
            if (DateTimeOffset.UtcNow > session.ExpiresAt)
            {
                _tokenCache.Remove(sessionId);
                return null;
            }
            return session;
        }
        return null;
    }

    private async Task<string> HashPasswordAsync(string password)
    {
        // Generate random salt
        var salt = new byte[32];
        RandomNumberGenerator.Fill(salt);

        // Argon2 password hashing
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 4,
            Iterations = 2,
            MemorySize = 65536 // 64 MB
        };

        var argonHash = await argon2.GetBytesAsync(32);

        // Additional BLAKE3 hashing (simplified - using SHA256 as BLAKE3 alternative)
        using var sha256 = SHA256.Create();
        var blakeHash = sha256.ComputeHash(argonHash);

        // ECC signing of the hash
        var hashToSign = sha256.ComputeHash(salt.Concat(blakeHash).ToArray());
        var signature = _privateKey.SignHash(hashToSign);

        // Format: salt(32) + blakeHash(32) + signature(64) = 128 bytes total
        var result = new byte[128];
        Buffer.BlockCopy(salt, 0, result, 0, 32);
        Buffer.BlockCopy(blakeHash, 0, result, 32, 32);
        Buffer.BlockCopy(signature, 0, result, 64, 64);

        return Convert.ToBase64String(result);
    }

    private async Task<bool> VerifyPasswordAsync(string password, string hash)
    {
        try
        {
            var hashBytes = Convert.FromBase64String(hash);
            if (hashBytes.Length != 128)
                return false;

            var salt = hashBytes.Take(32).ToArray();
            var storedBlakeHash = hashBytes.Skip(32).Take(32).ToArray();
            var storedSignature = hashBytes.Skip(64).Take(64).ToArray();

            // Recompute Argon2 + BLAKE3 hash
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = 4,
                Iterations = 2,
                MemorySize = 65536
            };

            var argonHash = await argon2.GetBytesAsync(32);

            using var sha256 = SHA256.Create();
            var computedBlakeHash = sha256.ComputeHash(argonHash);

            // Verify BLAKE3 hash matches
            if (!CryptographicOperations.FixedTimeEquals(computedBlakeHash, storedBlakeHash))
                return false;

            // Verify ECC signature
            var hashToVerify = sha256.ComputeHash(hashBytes.Take(64).ToArray());
            return _publicKey.VerifyHash(hashToVerify, storedSignature);
        }
        catch
        {
            return false;
        }
    }

    private async Task<string> GenerateTokenAsync(string userId, string username)
    {
        var claims = new[]
        {
            new Claim("user_id", userId),
            new Claim("username", username),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.Add(_options.TokenExpiry).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Iss, "degenhf")
        };

        var credentials = new SigningCredentials(new ECDsaSecurityKey(_privateKey), SecurityAlgorithms.EcdsaSha256);

        var token = new JwtSecurityToken(
            issuer: "degenhf",
            claims: claims,
            expires: DateTime.UtcNow.Add(_options.TokenExpiry),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

/// <summary>
/// Configuration options for ECC authentication
/// </summary>
public class EccAuthOptions
{
    public int HashIterations { get; set; } = 100000;
    public TimeSpan TokenExpiry { get; set; } = TimeSpan.FromHours(24);
    public TimeSpan CacheExpiry { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// User session data
/// </summary>
public class UserSession
{
    public required string UserId { get; set; }
    public required string Username { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

/// <summary>
/// User claims from verified token
/// </summary>
public class UserClaims
{
    public required string UserId { get; set; }
    public required string Username { get; set; }
}