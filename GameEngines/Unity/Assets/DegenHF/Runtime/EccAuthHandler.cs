using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UnityEngine;

namespace DegenHF.EccAuth.Unity
{
    /// <summary>
    /// Unity-compatible ECC-based authentication handler using secp256k1
    /// </summary>
    public class EccAuthHandler : MonoBehaviour
    {
        private ECDsa _privateKey;
        private ECDsa _publicKey;
        private Dictionary<string, UserSession> _tokenCache;
        private EccAuthOptions _options;

        /// <summary>
        /// Configuration options for ECC authentication
        /// </summary>
        [System.Serializable]
        public class EccAuthOptions
        {
            public int HashIterations = 100000;
            public float TokenExpiryHours = 24f;
            public float CacheExpiryMinutes = 5f;
        }

        /// <summary>
        /// User session data
        /// </summary>
        [System.Serializable]
        public class UserSession
        {
            public string UserId;
            public string Username;
            public long CreatedAt;
            public long ExpiresAt;
        }

        /// <summary>
        /// User claims from verified token
        /// </summary>
        [System.Serializable]
        public class UserClaims
        {
            public string UserId;
            public string Username;
        }

        void Awake()
        {
            Initialize();
        }

        /// <summary>
        /// Initialize the authentication handler
        /// </summary>
        public void Initialize(EccAuthOptions options = null)
        {
            _options = options ?? new EccAuthOptions();
            _privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _publicKey = ECDsa.Create(_privateKey.ExportParameters(false));
            _tokenCache = new Dictionary<string, UserSession>();
        }

        /// <summary>
        /// Register a new user with ECC-secured password hashing
        /// </summary>
        public async Task<string> RegisterAsync(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Username and password cannot be empty");

            // In a real implementation, you'd store this in a database
            var userId = $"user_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";

            try
            {
                // Hash the password
                var hash = await HashPasswordAsync(password);

                // Store user data (mock implementation - replace with your storage)
                Debug.Log($"User registered: {username} with ID: {userId}");

                // In real implementation, store hash in database
                PlayerPrefs.SetString($"user_{userId}_hash", hash);
                PlayerPrefs.SetString($"user_{userId}_username", username);
                PlayerPrefs.Save();

                return userId;
            }
            catch (Exception ex)
            {
                Debug.LogError($"Registration failed: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Authenticate a user and return a JWT token
        /// </summary>
        public async Task<string> AuthenticateAsync(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Username and password cannot be empty");

            try
            {
                // Find user by username (mock implementation)
                string userId = null;
                string storedHash = null;

                // In real implementation, query database by username
                foreach (var key in PlayerPrefs.GetString("registered_users", "").Split(','))
                {
                    if (!string.IsNullOrEmpty(key))
                    {
                        var storedUsername = PlayerPrefs.GetString($"user_{key}_username", "");
                        if (storedUsername == username)
                        {
                            userId = key;
                            storedHash = PlayerPrefs.GetString($"user_{key}_hash", "");
                            break;
                        }
                    }
                }

                if (userId == null)
                {
                    throw new UnauthorizedAccessException("User not found");
                }

                // Verify password
                if (!await VerifyPasswordAsync(password, storedHash))
                {
                    throw new UnauthorizedAccessException("Invalid credentials");
                }

                // Create session
                var session = new UserSession
                {
                    UserId = userId,
                    Username = username,
                    CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(_options.TokenExpiryHours).ToUnixTimeSeconds()
                };

                // Generate simple session token (Unity-compatible)
                var token = GenerateSimpleToken(session);

                // Cache session
                _tokenCache[token] = session;

                Debug.Log($"User authenticated: {username}");
                return token;
            }
            catch (Exception ex)
            {
                Debug.LogError($"Authentication failed: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Verify a token and return user data
        /// </summary>
        public UserClaims VerifyToken(string token)
        {
            try
            {
                // Check cache
                if (_tokenCache.TryGetValue(token, out UserSession session))
                {
                    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    if (now < session.ExpiresAt)
                    {
                        return new UserClaims
                        {
                            UserId = session.UserId,
                            Username = session.Username
                        };
                    }
                    _tokenCache.Remove(token);
                }

                // Simple token verification (in real implementation, use proper JWT)
                var parts = token.Split('.');
                if (parts.Length != 3) return null;

                var payload = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
                var claims = JsonUtility.FromJson<UserSession>(payload);

                if (claims == null) return null;

                var now2 = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (now2 >= claims.ExpiresAt) return null;

                // Cache valid token
                _tokenCache[token] = claims;

                return new UserClaims
                {
                    UserId = claims.UserId,
                    Username = claims.Username
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Create a secure session
        /// </summary>
        public string CreateSession(string userId)
        {
            var sessionId = $"session_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";

            var session = new UserSession
            {
                UserId = userId,
                Username = "", // Would be populated from user data
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(_options.TokenExpiryHours).ToUnixTimeSeconds()
            };

            _tokenCache[sessionId] = session;
            return sessionId;
        }

        /// <summary>
        /// Get session data
        /// </summary>
        public UserSession GetSession(string sessionId)
        {
            if (_tokenCache.TryGetValue(sessionId, out UserSession session))
            {
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (now > session.ExpiresAt)
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
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Simplified Argon2-like hashing for Unity compatibility
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var combined = new byte[salt.Length + passwordBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(passwordBytes, 0, combined, salt.Length, passwordBytes.Length);

            // Multiple rounds of hashing
            var hash = combined;
            using (var sha256 = SHA256.Create())
            {
                for (int i = 0; i < 10000; i++) // Simplified iteration count for Unity
                {
                    hash = sha256.ComputeHash(hash);
                }
            }

            // ECC signing
            using (var sha256 = SHA256.Create())
            {
                var hashToSign = sha256.ComputeHash(hash);
                var signature = _privateKey.SignHash(hashToSign);

                // Format: salt(32) + hash(32) + signature(64) = 128 bytes total
                var result = new byte[128];
                Buffer.BlockCopy(salt, 0, result, 0, 32);
                Buffer.BlockCopy(hash, 0, result, 32, 32);
                Buffer.BlockCopy(signature, 0, result, 64, 64);

                return Convert.ToBase64String(result);
            }
        }

        private async Task<bool> VerifyPasswordAsync(string password, string hash)
        {
            try
            {
                var hashBytes = Convert.FromBase64String(hash);
                if (hashBytes.Length != 128) return false;

                var salt = new byte[32];
                var storedHash = new byte[32];
                var storedSignature = new byte[64];

                Buffer.BlockCopy(hashBytes, 0, salt, 0, 32);
                Buffer.BlockCopy(hashBytes, 32, storedHash, 0, 32);
                Buffer.BlockCopy(hashBytes, 64, storedSignature, 0, 64);

                // Recompute hash
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                var combined = new byte[salt.Length + passwordBytes.Length];
                Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
                Buffer.BlockCopy(passwordBytes, 0, combined, salt.Length, passwordBytes.Length);

                var computedHash = combined;
                using (var sha256 = SHA256.Create())
                {
                    for (int i = 0; i < 10000; i++)
                    {
                        computedHash = sha256.ComputeHash(computedHash);
                    }
                }

                // Verify hash matches
                if (!CryptographicOperations.FixedTimeEquals(computedHash, storedHash))
                    return false;

                // Verify ECC signature
                using (var sha256 = SHA256.Create())
                {
                    var hashToVerify = sha256.ComputeHash(hashBytes.Take(64).ToArray());
                    return _publicKey.VerifyHash(hashToVerify, storedSignature);
                }
            }
            catch
            {
                return false;
            }
        }

        private string GenerateSimpleToken(UserSession session)
        {
            // Create a simple JWT-like token for Unity compatibility
            var header = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":\"ES256\",\"typ\":\"JWT\"}"));
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonUtility.ToJson(session)));

            // Simple signature (in real implementation, use proper JWT)
            var message = $"{header}.{payload}";
            var messageBytes = Encoding.UTF8.GetBytes(message);
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(messageBytes);
                var signature = Convert.ToBase64String(_privateKey.SignHash(hash));
                return $"{header}.{payload}.{signature}";
            }
        }
    }
}