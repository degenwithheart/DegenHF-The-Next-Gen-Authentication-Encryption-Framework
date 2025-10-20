using UnityEngine;
using UnityEngine.UI;
using DegenHF.EccAuth.Unity;
using System.Threading.Tasks;

namespace DegenHF.EccAuth.Unity.Examples
{
    /// <summary>
    /// Example authentication manager for Unity games
    /// Attach this to a GameObject in your scene
    /// </summary>
    public class AuthManager : MonoBehaviour
    {
        [Header("UI References")]
        [SerializeField] private InputField usernameInput;
        [SerializeField] private InputField passwordInput;
        [SerializeField] private Button registerButton;
        [SerializeField] private Button loginButton;
        [SerializeField] private Text statusText;

        private EccAuthHandler _authHandler;

        void Start()
        {
            _authHandler = gameObject.AddComponent<EccAuthHandler>();
            _authHandler.Initialize();

            registerButton.onClick.AddListener(OnRegisterClicked);
            loginButton.onClick.AddListener(OnLoginClicked);

            UpdateStatus("Ready for authentication");
        }

        private async void OnRegisterClicked()
        {
            if (string.IsNullOrEmpty(usernameInput.text) || string.IsNullOrEmpty(passwordInput.text))
            {
                UpdateStatus("Please enter username and password");
                return;
            }

            UpdateStatus("Registering...");

            try
            {
                var userId = await _authHandler.RegisterAsync(usernameInput.text, passwordInput.text);
                UpdateStatus($"Registration successful! User ID: {userId}");

                // Store registered user for demo
                var registeredUsers = PlayerPrefs.GetString("registered_users", "");
                if (!registeredUsers.Contains(userId))
                {
                    registeredUsers += (string.IsNullOrEmpty(registeredUsers) ? "" : ",") + userId;
                    PlayerPrefs.SetString("registered_users", registeredUsers);
                    PlayerPrefs.Save();
                }
            }
            catch (System.Exception ex)
            {
                UpdateStatus($"Registration failed: {ex.Message}");
            }
        }

        private async void OnLoginClicked()
        {
            if (string.IsNullOrEmpty(usernameInput.text) || string.IsNullOrEmpty(passwordInput.text))
            {
                UpdateStatus("Please enter username and password");
                return;
            }

            UpdateStatus("Authenticating...");

            try
            {
                var token = await _authHandler.AuthenticateAsync(usernameInput.text, passwordInput.text);

                // Verify the token
                var claims = _authHandler.VerifyToken(token);

                if (claims != null)
                {
                    UpdateStatus($"Login successful! Welcome {claims.Username} (ID: {claims.UserId})");

                    // Store token for session
                    PlayerPrefs.SetString("auth_token", token);
                    PlayerPrefs.SetString("user_id", claims.UserId);
                    PlayerPrefs.Save();
                }
                else
                {
                    UpdateStatus("Token verification failed");
                }
            }
            catch (System.Exception ex)
            {
                UpdateStatus($"Login failed: {ex.Message}");
            }
        }

        private void UpdateStatus(string message)
        {
            if (statusText != null)
            {
                statusText.text = message;
            }
            Debug.Log($"Auth Status: {message}");
        }

        void OnDestroy()
        {
            if (registerButton != null) registerButton.onClick.RemoveListener(OnRegisterClicked);
            if (loginButton != null) loginButton.onClick.RemoveListener(OnLoginClicked);
        }
    }
}