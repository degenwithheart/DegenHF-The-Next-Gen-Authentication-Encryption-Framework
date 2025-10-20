#if GODOT
using Godot;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DegenHF.Godot
{
    /// <summary>
    /// Godot extension for DegenHF ECC authentication
    ///
    /// Provides easy-to-use authentication integration for Godot games
    /// with automatic scene management and GDScript callbacks.
    /// </summary>
    [Tool]
    public class AuthExtension : Node
    {
        /// <summary>
        /// Authentication callback types
        /// </summary>
        public delegate void AuthCallback(bool success, string message);
        public delegate void RegisterCallback(bool success, string userId, string message);
        public delegate void LoginCallback(bool success, string token, string userId, string username, string message);

        private static AuthExtension _instance;
        private ECC.AuthHandler _authHandler;
        private bool _initialized;

        /// <summary>
        /// Get singleton instance
        /// </summary>
        /// <returns>AuthExtension instance</returns>
        public static AuthExtension GetInstance()
        {
            if (_instance == null)
            {
                _instance = new AuthExtension();
            }
            return _instance;
        }

        public override void _Ready()
        {
            if (_instance == null)
            {
                _instance = this;
            }
        }

        /// <summary>
        /// Initialize the extension
        /// </summary>
        /// <param name="config">Authentication configuration</param>
        /// <returns>true if initialization successful</returns>
        public bool Init(ECC.AuthHandler.Config config = null)
        {
            if (_initialized)
            {
                return true;
            }

            _authHandler = new ECC.AuthHandler(config);
            if (!_authHandler.Initialize())
            {
                GD.PrintErr("Failed to initialize ECC Auth Handler");
                return false;
            }

            _initialized = true;
            GD.Print("DegenHF Godot Auth Extension initialized successfully");
            return true;
        }

        /// <summary>
        /// Register a new user
        /// </summary>
        /// <param name="username">Username for registration</param>
        /// <param name="password">Password for registration</param>
        /// <param name="callback">Callback function for result</param>
        public void RegisterUser(string username, string password, RegisterCallback callback = null)
        {
            if (!_initialized || _authHandler == null)
            {
                callback?.Invoke(false, "", "Extension not initialized");
                return;
            }

            // Perform registration asynchronously
            Task.Run(() =>
            {
                var result = _authHandler.RegisterUser(username, password);
                CallDeferred("emit_signal", "register_completed", result.Success, result.UserId, result.ErrorMessage);

                if (callback != null)
                {
                    CallDeferred("invoke_callback", callback.Method.Name, result.Success, result.UserId, result.ErrorMessage);
                }
            });
        }

        /// <summary>
        /// Login user
        /// </summary>
        /// <param name="username">Username for login</param>
        /// <param name="password">Password for login</param>
        /// <param name="callback">Callback function for result</param>
        public void LoginUser(string username, string password, LoginCallback callback = null)
        {
            if (!_initialized || _authHandler == null)
            {
                callback?.Invoke(false, "", "", "", "Extension not initialized");
                return;
            }

            // Perform login asynchronously
            Task.Run(() =>
            {
                var result = _authHandler.AuthenticateUser(username, password);
                CallDeferred("emit_signal", "login_completed", result.Success, result.Token, result.UserId, result.Username, result.ErrorMessage);

                if (callback != null)
                {
                    CallDeferred("invoke_callback", callback.Method.Name, result.Success, result.Token, result.UserId, result.Username, result.ErrorMessage);
                }
            });
        }

        /// <summary>
        /// Logout current user
        /// </summary>
        /// <param name="callback">Callback function for result</param>
        public void LogoutUser(AuthCallback callback = null)
        {
            if (!_initialized || _authHandler == null)
            {
                callback?.Invoke(false, "Extension not initialized");
                return;
            }

            _authHandler.Logout();
            _authHandler.SaveAuthData();

            callback?.Invoke(true, "Logged out successfully");
        }

        /// <summary>
        /// Check if user is logged in
        /// </summary>
        /// <returns>true if user is logged in</returns>
        public bool IsLoggedIn()
        {
            if (!_initialized || _authHandler == null)
            {
                return false;
            }
            return _authHandler.IsUserLoggedIn();
        }

        /// <summary>
        /// Get current user ID
        /// </summary>
        /// <returns>Current user ID or empty string</returns>
        public string GetCurrentUserId()
        {
            if (!_initialized || _authHandler == null)
            {
                return "";
            }
            return _authHandler.GetCurrentUserId();
        }

        /// <summary>
        /// Get current username
        /// </summary>
        /// <returns>Current username or empty string</returns>
        public string GetCurrentUsername()
        {
            if (!_initialized || _authHandler == null)
            {
                return "";
            }
            return _authHandler.GetCurrentUsername();
        }

        /// <summary>
        /// Verify authentication token
        /// </summary>
        /// <param name="token">Token to verify</param>
        /// <param name="callback">Callback function for result</param>
        public void VerifyToken(string token, AuthCallback callback = null)
        {
            if (!_initialized || _authHandler == null)
            {
                callback?.Invoke(false, "Extension not initialized");
                return;
            }

            // Perform verification asynchronously
            Task.Run(() =>
            {
                var result = _authHandler.VerifyToken(token);
                CallDeferred("emit_signal", "verify_completed", result.Valid, result.Valid ? "Token valid" : result.ErrorMessage);

                if (callback != null)
                {
                    CallDeferred("invoke_callback", callback.Method.Name, result.Valid, result.Valid ? "Token valid" : result.ErrorMessage);
                }
            });
        }

        /// <summary>
        /// Create a secure session
        /// </summary>
        /// <param name="callback">Callback function with session ID</param>
        public void CreateSession(Action<string> callback = null)
        {
            if (!_initialized || _authHandler == null)
            {
                callback?.Invoke("");
                return;
            }

            string userId = _authHandler.GetCurrentUserId();
            if (string.IsNullOrEmpty(userId))
            {
                callback?.Invoke("");
                return;
            }

            string sessionId = _authHandler.CreateSession(userId);
            callback?.Invoke(sessionId);
        }

        /// <summary>
        /// Get session information
        /// </summary>
        /// <param name="sessionId">Session ID to query</param>
        /// <param name="callback">Callback function with user info</param>
        public void GetSessionInfo(string sessionId, Action<bool, string, string> callback = null)
        {
            if (!_initialized || _authHandler == null)
            {
                callback?.Invoke(false, "", "");
                return;
            }

            string userId, username;
            bool valid = _authHandler.GetSession(sessionId, out userId, out username);
            callback?.Invoke(valid, userId, username);
        }

        /// <summary>
        /// Save authentication state
        /// </summary>
        public void SaveAuthState()
        {
            if (_initialized && _authHandler != null)
            {
                _authHandler.SaveAuthData();
            }
        }

        /// <summary>
        /// Load authentication state
        /// </summary>
        public void LoadAuthState()
        {
            if (_initialized && _authHandler != null)
            {
                _authHandler.LoadAuthData();
            }
        }

        /// <summary>
        /// Get the underlying auth handler
        /// </summary>
        /// <returns>Pointer to ECC auth handler</returns>
        public ECC.AuthHandler GetAuthHandler()
        {
            return _authHandler;
        }

        // Signal definitions for GDScript
        [Signal]
        public delegate void RegisterCompletedEventHandler(bool success, string userId, string message);

        [Signal]
        public delegate void LoginCompletedEventHandler(bool success, string token, string userId, string username, string message);

        [Signal]
        public delegate void VerifyCompletedEventHandler(bool valid, string message);

        // Helper method for deferred callback invocation
        private void InvokeCallback(string methodName, params object[] args)
        {
            // This method is called via CallDeferred to ensure thread safety
            // The actual callback invocation would be handled by the specific method
        }
    }
}
#endif