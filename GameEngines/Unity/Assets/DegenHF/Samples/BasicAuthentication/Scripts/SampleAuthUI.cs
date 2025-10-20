using UnityEngine;
using UnityEngine.UI;
using TMPro;
using DegenHF.EccAuth.Unity;
using System.Threading.Tasks;

namespace DegenHF.EccAuth.Unity.Samples
{
    /// <summary>
    /// Sample authentication UI for Unity
    /// This demonstrates how to integrate DegenHF authentication into a Unity game
    /// </summary>
    public class SampleAuthUI : MonoBehaviour
    {
        [Header("UI Components")]
        [SerializeField] private TMP_InputField usernameField;
        [SerializeField] private TMP_InputField passwordField;
        [SerializeField] private Button registerButton;
        [SerializeField] private Button loginButton;
        [SerializeField] private Button logoutButton;
        [SerializeField] private TMP_Text statusText;
        [SerializeField] private TMP_Text userInfoText;

        [Header("Game Objects")]
        [SerializeField] private GameObject loginPanel;
        [SerializeField] private GameObject gamePanel;

        private EccAuthHandler _authHandler;
        private string _currentToken;
        private EccAuthHandler.UserClaims _currentUser;

        void Start()
        {
            // Initialize authentication handler
            _authHandler = gameObject.AddComponent<EccAuthHandler>();
            _authHandler.Initialize();

            // Setup button listeners
            registerButton.onClick.AddListener(OnRegisterClick);
            loginButton.onClick.AddListener(OnLoginClick);
            logoutButton.onClick.AddListener(OnLogoutClick);

            // Check for existing session
            CheckExistingSession();

            UpdateUI();
            SetStatus("Ready for authentication");
        }

        private void CheckExistingSession()
        {
            var savedToken = PlayerPrefs.GetString("auth_token", "");
            if (!string.IsNullOrEmpty(savedToken))
            {
                var claims = _authHandler.VerifyToken(savedToken);
                if (claims != null)
                {
                    _currentToken = savedToken;
                    _currentUser = claims;
                    SetStatus($"Welcome back, {claims.Username}!");
                    ShowGamePanel();
                    return;
                }
            }

            ShowLoginPanel();
        }

        private async void OnRegisterClick()
        {
            var username = usernameField.text.Trim();
            var password = passwordField.text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                SetStatus("Please enter both username and password");
                return;
            }

            if (password.Length < 6)
            {
                SetStatus("Password must be at least 6 characters");
                return;
            }

            SetStatus("Registering...");
            DisableButtons();

            try
            {
                var userId = await _authHandler.RegisterAsync(username, password);
                SetStatus($"Registration successful! User ID: {userId}");

                // Auto-login after registration
                await PerformLogin(username, password);
            }
            catch (System.Exception ex)
            {
                SetStatus($"Registration failed: {ex.Message}");
                EnableButtons();
            }
        }

        private async void OnLoginClick()
        {
            var username = usernameField.text.Trim();
            var password = passwordField.text.Trim();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                SetStatus("Please enter both username and password");
                return;
            }

            await PerformLogin(username, password);
        }

        private async Task PerformLogin(string username, string password)
        {
            SetStatus("Logging in...");
            DisableButtons();

            try
            {
                _currentToken = await _authHandler.AuthenticateAsync(username, password);
                _currentUser = _authHandler.VerifyToken(_currentToken);

                if (_currentUser != null)
                {
                    // Save session
                    PlayerPrefs.SetString("auth_token", _currentToken);
                    PlayerPrefs.SetString("user_id", _currentUser.UserId);
                    PlayerPrefs.Save();

                    SetStatus($"Login successful! Welcome {_currentUser.Username}");
                    ShowGamePanel();
                }
                else
                {
                    SetStatus("Login failed: Token verification error");
                    EnableButtons();
                }
            }
            catch (System.Exception ex)
            {
                SetStatus($"Login failed: {ex.Message}");
                EnableButtons();
            }
        }

        private void OnLogoutClick()
        {
            // Clear session
            _currentToken = null;
            _currentUser = null;

            PlayerPrefs.DeleteKey("auth_token");
            PlayerPrefs.DeleteKey("user_id");
            PlayerPrefs.Save();

            SetStatus("Logged out successfully");
            ShowLoginPanel();
        }

        private void ShowLoginPanel()
        {
            if (loginPanel != null) loginPanel.SetActive(true);
            if (gamePanel != null) gamePanel.SetActive(false);
        }

        private void ShowGamePanel()
        {
            if (loginPanel != null) loginPanel.SetActive(false);
            if (gamePanel != null) gamePanel.SetActive(true);

            if (userInfoText != null && _currentUser != null)
            {
                userInfoText.text = $"Player: {_currentUser.Username}\nID: {_currentUser.UserId}";
            }
        }

        private void SetStatus(string message)
        {
            if (statusText != null)
            {
                statusText.text = message;
            }
            Debug.Log($"Auth Status: {message}");
        }

        private void DisableButtons()
        {
            registerButton.interactable = false;
            loginButton.interactable = false;
        }

        private void EnableButtons()
        {
            registerButton.interactable = true;
            loginButton.interactable = true;
        }

        private void UpdateUI()
        {
            if (_currentUser != null)
            {
                ShowGamePanel();
            }
            else
            {
                ShowLoginPanel();
            }
        }

        void OnDestroy()
        {
            // Cleanup listeners
            if (registerButton != null) registerButton.onClick.RemoveListener(OnRegisterClick);
            if (loginButton != null) loginButton.onClick.RemoveListener(OnLoginClick);
            if (logoutButton != null) logoutButton.onClick.RemoveListener(OnLogoutClick);
        }

        // Example methods for game integration
        public bool IsUserLoggedIn()
        {
            return _currentUser != null && !string.IsNullOrEmpty(_currentToken);
        }

        public string GetCurrentUserId()
        {
            return _currentUser?.UserId ?? "";
        }

        public string GetCurrentUsername()
        {
            return _currentUser?.Username ?? "";
        }

        public string GetAuthToken()
        {
            return _currentToken ?? "";
        }

        public async Task<bool> ValidateCurrentSession()
        {
            if (string.IsNullOrEmpty(_currentToken)) return false;

            _currentUser = _authHandler.VerifyToken(_currentToken);
            return _currentUser != null;
        }
    }
}