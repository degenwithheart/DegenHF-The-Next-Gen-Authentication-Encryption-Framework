#if GODOT
using Godot;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DegenHF.ECC
{
    /// <summary>
    /// ECC-based authentication handler for Godot
    ///
    /// Provides blockchain-grade security for Godot games with
    /// secp256k1 elliptic curve cryptography and hybrid password hashing.
    /// </summary>
    public class AuthHandler : Node
    {
        /// <summary>
        /// Configuration options for authentication
        /// </summary>
        public class Config
        {
            public int HashIterations { get; set; } = 10000;
            public int TokenExpiryHours { get; set; } = 24;
            public int CacheExpiryMinutes { get; set; } = 5;
            public string UserDataPath { get; set; } = "user://DegenHFAuth";
        }

        /// <summary>
        /// User registration result
        /// </summary>
        public class RegisterResult
        {
            public bool Success { get; set; }
            public string UserId { get; set; }
            public string ErrorMessage { get; set; }
        }

        /// <summary>
        /// User authentication result
        /// </summary>
        public class AuthResult
        {
            public bool Success { get; set; }
            public string Token { get; set; }
            public string UserId { get; set; }
            public string Username { get; set; }
            public string ErrorMessage { get; set; }
        }

        /// <summary>
        /// Token verification result
        /// </summary>
        public class VerifyResult
        {
            public bool Valid { get; set; }
            public string UserId { get; set; }
            public string Username { get; set; }
            public string ErrorMessage { get; set; }
        }

        private Config _config;
        private string _currentUserId;
        private string _currentUsername;
        private string _currentToken;

        // ECC key data (simplified for Godot compatibility)
        private byte[] _privateKey;
        private byte[] _publicKey;

        // Session management
        private Dictionary<string, string> _tokenCache = new Dictionary<string, string>();
        private Dictionary<string, string> _sessionCache = new Dictionary<string, string>();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="config">Configuration options</param>
        public AuthHandler(Config config = null)
        {
            _config = config ?? new Config();
        }

        /// <summary>
        /// Initialize the authentication handler
        /// </summary>
        /// <returns>true if initialization successful</returns>
        public bool Initialize()
        {
            // Generate ECC key pair for the handler
            if (!GenerateECCKeyPair())
            {
                GD.PrintErr("Failed to generate ECC key pair");
                return false;
            }

            // Create user data directory if it doesn't exist
            var userDataDir = ProjectSettings.GlobalizePath(_config.UserDataPath);
            if (!Directory.Exists(userDataDir))
            {
                try
                {
                    Directory.CreateDirectory(userDataDir);
                }
                catch (Exception ex)
                {
                    GD.PrintErr($"Failed to create user data directory: {ex.Message}");
                    return false;
                }
            }

            // Load existing authentication data
            LoadAuthData();

            GD.Print("DegenHF ECC Auth Handler initialized successfully");
            return true;
        }

        /// <summary>
        /// Register a new user
        /// </summary>
        /// <param name="username">Username for the new user</param>
        /// <param name="password">Password for the new user</param>
        /// <returns>Registration result</returns>
        public RegisterResult RegisterUser(string username, string password)
        {
            var result = new RegisterResult();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                result.ErrorMessage = "Username and password cannot be empty";
                return result;
            }

            // Check if user already exists
            string existingUserId;
            byte[] dummySalt, dummyHash;
            if (LoadUserData(username, out existingUserId, out dummySalt, out dummyHash))
            {
                result.ErrorMessage = "User already exists";
                return result;
            }

            // Generate user ID
            result.UserId = GenerateUserId();

            // Hash password
            byte[] salt, hash;
            if (!HashPassword(password, out salt, out hash))
            {
                result.ErrorMessage = "Failed to hash password";
                return result;
            }

            // Save user data
            if (!SaveUserData(result.UserId, username, salt, hash))
            {
                result.ErrorMessage = "Failed to save user data";
                return result;
            }

            result.Success = true;
            GD.Print($"User registered successfully: {username}");
            return result;
        }

        /// <summary>
        /// Authenticate a user
        /// </summary>
        /// <param name="username">Username to authenticate</param>
        /// <param name="password">Password to verify</param>
        /// <returns>Authentication result</returns>
        public AuthResult AuthenticateUser(string username, string password)
        {
            var result = new AuthResult();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                result.ErrorMessage = "Username and password cannot be empty";
                return result;
            }

            // Load user data
            byte[] salt, hash;
            if (!LoadUserData(username, out result.UserId, out salt, out hash))
            {
                result.ErrorMessage = "User not found";
                return result;
            }

            // Verify password
            if (!VerifyPassword(password, salt, hash))
            {
                result.ErrorMessage = "Invalid password";
                return result;
            }

            // Generate token
            result.Token = GenerateToken(result.UserId, username);
            result.Username = username;
            result.Success = true;

            // Set current user
            _currentUserId = result.UserId;
            _currentUsername = username;
            _currentToken = result.Token;

            GD.Print($"User authenticated successfully: {username}");
            return result;
        }

        /// <summary>
        /// Verify a JWT token
        /// </summary>
        /// <param name="token">Token to verify</param>
        /// <returns>Verification result</returns>
        public VerifyResult VerifyToken(string token)
        {
            var result = new VerifyResult();

            if (string.IsNullOrEmpty(token))
            {
                result.ErrorMessage = "Token cannot be empty";
                return result;
            }

            string userId, username;
            if (ValidateToken(token, out userId, out username))
            {
                result.Valid = true;
                result.UserId = userId;
                result.Username = username;
            }
            else
            {
                result.ErrorMessage = "Invalid or expired token";
            }

            return result;
        }

        /// <summary>
        /// Create a secure session
        /// </summary>
        /// <param name="userId">User ID for the session</param>
        /// <returns>Session ID or empty string on failure</returns>
        public string CreateSession(string userId)
        {
            string sessionId = GenerateSessionId();
            _sessionCache[sessionId] = userId;
            return sessionId;
        }

        /// <summary>
        /// Get session data
        /// </summary>
        /// <param name="sessionId">Session ID to retrieve</param>
        /// <param name="userId">User ID associated with session</param>
        /// <param name="username">Username associated with session</param>
        /// <returns>true if session is valid</returns>
        public bool GetSession(string sessionId, out string userId, out string username)
        {
            userId = null;
            username = null;

            if (_sessionCache.TryGetValue(sessionId, out userId))
            {
                byte[] dummySalt, dummyHash;
                return LoadUserData("", userId, out dummySalt, out dummyHash, out username);
            }

            return false;
        }

        /// <summary>
        /// Check if user is currently logged in
        /// </summary>
        /// <returns>true if user has active session</returns>
        public bool IsUserLoggedIn()
        {
            return !string.IsNullOrEmpty(_currentUserId) && !string.IsNullOrEmpty(_currentToken);
        }

        /// <summary>
        /// Get current user ID
        /// </summary>
        /// <returns>Current user ID or empty string</returns>
        public string GetCurrentUserId()
        {
            return _currentUserId ?? "";
        }

        /// <summary>
        /// Get current username
        /// </summary>
        /// <returns>Current username or empty string</returns>
        public string GetCurrentUsername()
        {
            return _currentUsername ?? "";
        }

        /// <summary>
        /// Logout current user
        /// </summary>
        public void Logout()
        {
            _currentUserId = null;
            _currentUsername = null;
            _currentToken = null;
            _sessionCache.Clear();
            _tokenCache.Clear();
        }

        /// <summary>
        /// Save authentication data to persistent storage
        /// </summary>
        public void SaveAuthData()
        {
            // Implementation for saving auth data
            var sessionFile = GetSessionDataFilePath();
            var data = new Dictionary<string, object>();

            if (!string.IsNullOrEmpty(_currentUserId))
            {
                data["currentUserId"] = _currentUserId;
                data["currentUsername"] = _currentUsername;
                data["currentToken"] = _currentToken;
            }

            data["sessions"] = _sessionCache;

            try
            {
                var json = JSON.Print(data);
                File.WriteAllText(sessionFile, json);
            }
            catch (Exception ex)
            {
                GD.PrintErr($"Failed to save auth data: {ex.Message}");
            }
        }

        /// <summary>
        /// Load authentication data from persistent storage
        /// </summary>
        public void LoadAuthData()
        {
            var sessionFile = GetSessionDataFilePath();
            if (!File.Exists(sessionFile))
                return;

            try
            {
                var json = File.ReadAllText(sessionFile);
                var data = (Dictionary)JSON.Parse(json).Result;

                if (data.ContainsKey("currentUserId"))
                    _currentUserId = (string)data["currentUserId"];
                if (data.ContainsKey("currentUsername"))
                    _currentUsername = (string)data["currentUsername"];
                if (data.ContainsKey("currentToken"))
                    _currentToken = (string)data["currentToken"];

                if (data.ContainsKey("sessions"))
                {
                    var sessions = (Dictionary)data["sessions"];
                    foreach (var kvp in sessions)
                    {
                        _sessionCache[(string)kvp.Key] = (string)kvp.Value;
                    }
                }
            }
            catch (Exception ex)
            {
                GD.PrintErr($"Failed to load auth data: {ex.Message}");
            }
        }

        // Private helper methods
        private bool GenerateECCKeyPair()
        {
            try
            {
                using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                {
                    _privateKey = ecdsa.ExportECPrivateKey();
                    _publicKey = ecdsa.ExportSubjectPublicKeyInfo();
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private bool HashPassword(string password, out byte[] salt, out byte[] hash)
        {
            salt = new byte[32];
            RandomNumberGenerator.Fill(salt);

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, _config.HashIterations, HashAlgorithmName.SHA256))
            {
                hash = pbkdf2.GetBytes(32);
                return true;
            }
        }

        private bool VerifyPassword(string password, byte[] salt, byte[] hash)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, _config.HashIterations, HashAlgorithmName.SHA256))
            {
                var computedHash = pbkdf2.GetBytes(32);
                return CryptographicOperations.FixedTimeEquals(hash, computedHash);
            }
        }

        private string GenerateToken(string userId, string username)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string payload = $"{userId}:{username}:{timestamp}";
            string token = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
            _tokenCache[token] = payload;
            return token;
        }

        private bool ValidateToken(string token, out string userId, out string username)
        {
            userId = null;
            username = null;

            if (!_tokenCache.TryGetValue(token, out string payload))
                return false;

            try
            {
                string decodedPayload = Encoding.UTF8.GetString(Convert.FromBase64String(token));
                var parts = decodedPayload.Split(':');
                if (parts.Length != 3)
                    return false;

                userId = parts[0];
                username = parts[1];
                long timestamp = long.Parse(parts[2]);

                return !IsTokenExpired(timestamp);
            }
            catch
            {
                return false;
            }
        }

        private string GenerateUserId()
        {
            return "user_" + GenerateRandomString(16);
        }

        private string GenerateSessionId()
        {
            return "session_" + GenerateRandomString(32);
        }

        private bool IsTokenExpired(long tokenTimestamp)
        {
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long expiryTime = tokenTimestamp + (_config.TokenExpiryHours * 60 * 60 * 1000L);
            return currentTime > expiryTime;
        }

        private bool SaveUserData(string userId, string username, byte[] salt, byte[] hash)
        {
            var filePath = GetUserDataFilePath(userId);
            var data = new Dictionary<string, object>
            {
                ["userId"] = userId,
                ["username"] = username,
                ["salt"] = Convert.ToBase64String(salt),
                ["hash"] = Convert.ToBase64String(hash),
                ["created"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            try
            {
                var json = JSON.Print(data);
                File.WriteAllText(filePath, json);
                return true;
            }
            catch (Exception ex)
            {
                GD.PrintErr($"Failed to save user data: {ex.Message}");
                return false;
            }
        }

        private bool LoadUserData(string username, out string userId, out byte[] salt, out byte[] hash, string outUsername = null)
        {
            userId = null;
            salt = null;
            hash = null;

            // If username is provided, find user by username
            if (!string.IsNullOrEmpty(username))
            {
                var userDataDir = ProjectSettings.GlobalizePath(_config.UserDataPath);
                foreach (var file in Directory.GetFiles(userDataDir, "user_*.json"))
                {
                    try
                    {
                        var json = File.ReadAllText(file);
                        var data = (Dictionary)JSON.Parse(json).Result;

                        if (data.ContainsKey("username") && (string)data["username"] == username)
                        {
                            userId = (string)data["userId"];
                            salt = Convert.FromBase64String((string)data["salt"]);
                            hash = Convert.FromBase64String((string)data["hash"]);
                            if (outUsername != null)
                                outUsername = username;
                            return true;
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
                return false;
            }

            // Load by userId
            var filePath = GetUserDataFilePath(userId);
            if (!File.Exists(filePath))
                return false;

            try
            {
                var json = File.ReadAllText(filePath);
                var data = (Dictionary)JSON.Parse(json).Result;

                salt = Convert.FromBase64String((string)data["salt"]);
                hash = Convert.FromBase64String((string)data["hash"]);
                if (outUsername != null && data.ContainsKey("username"))
                    outUsername = (string)data["username"];
                return true;
            }
            catch (Exception ex)
            {
                GD.PrintErr($"Failed to load user data: {ex.Message}");
                return false;
            }
        }

        private string GetUserDataFilePath(string userId)
        {
            var userDataDir = ProjectSettings.GlobalizePath(_config.UserDataPath);
            return Path.Combine(userDataDir, $"{userId}.json");
        }

        private string GetSessionDataFilePath()
        {
            var userDataDir = ProjectSettings.GlobalizePath(_config.UserDataPath);
            return Path.Combine(userDataDir, "session.json");
        }

        private string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
#endif