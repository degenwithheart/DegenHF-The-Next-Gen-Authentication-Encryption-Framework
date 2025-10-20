#ifndef __DEGEN_HF_ECC_AUTH_H__
#define __DEGEN_HF_ECC_AUTH_H__

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace DegenHF {
namespace ECC {

/**
 * @brief ECC-based authentication handler for Cocos2d-x
 *
 * Provides blockchain-grade security for Cocos2d-x games with
 * secp256k1 elliptic curve cryptography and hybrid password hashing.
 */
class AuthHandler {
public:
    /**
     * @brief Configuration options for authentication
     */
    struct Config {
        int hashIterations = 10000;           /**< Password hashing rounds */
        int tokenExpiryHours = 24;            /**< Token lifetime in hours */
        int cacheExpiryMinutes = 5;           /**< Cache lifetime in minutes */
        std::string userDataPath = "UserData"; /**< Path for storing user data */
    };

    /**
     * @brief User registration result
     */
    struct RegisterResult {
        bool success = false;
        std::string userId;
        std::string errorMessage;
    };

    /**
     * @brief User authentication result
     */
    struct AuthResult {
        bool success = false;
        std::string token;
        std::string userId;
        std::string username;
        std::string errorMessage;
    };

    /**
     * @brief Token verification result
     */
    struct VerifyResult {
        bool valid = false;
        std::string userId;
        std::string username;
        std::string errorMessage;
    };

    /**
     * @brief Constructor
     * @param config Configuration options
     */
    explicit AuthHandler(const Config& config = Config());

    /**
     * @brief Destructor
     */
    ~AuthHandler();

    /**
     * @brief Initialize the authentication handler
     * @return true if initialization successful
     */
    bool initialize();

    /**
     * @brief Register a new user
     * @param username Username for the new user
     * @param password Password for the new user
     * @return Registration result
     */
    RegisterResult registerUser(const std::string& username, const std::string& password);

    /**
     * @brief Authenticate a user
     * @param username Username to authenticate
     * @param password Password to verify
     * @return Authentication result
     */
    AuthResult authenticateUser(const std::string& username, const std::string& password);

    /**
     * @brief Verify a JWT token
     * @param token Token to verify
     * @return Verification result
     */
    VerifyResult verifyToken(const std::string& token);

    /**
     * @brief Create a secure session
     * @param userId User ID for the session
     * @return Session ID or empty string on failure
     */
    std::string createSession(const std::string& userId);

    /**
     * @brief Get session data
     * @param sessionId Session ID to retrieve
     * @param[out] userId User ID associated with session
     * @param[out] username Username associated with session
     * @return true if session is valid
     */
    bool getSession(const std::string& sessionId, std::string& userId, std::string& username);

    /**
     * @brief Check if user is currently logged in
     * @return true if user has active session
     */
    bool isUserLoggedIn() const;

    /**
     * @brief Get current user ID
     * @return Current user ID or empty string
     */
    std::string getCurrentUserId() const;

    /**
     * @brief Get current username
     * @return Current username or empty string
     */
    std::string getCurrentUsername() const;

    /**
     * @brief Logout current user
     */
    void logout();

    /**
     * @brief Save authentication data to persistent storage
     */
    void saveAuthData();

    /**
     * @brief Load authentication data from persistent storage
     */
    void loadAuthData();

private:
    Config m_config;
    std::string m_currentUserId;
    std::string m_currentUsername;
    std::string m_currentToken;

    // ECC key data (simplified for Cocos2d-x compatibility)
    std::vector<uint8_t> m_privateKey;
    std::vector<uint8_t> m_publicKey;

    // Session management
    std::unordered_map<std::string, std::string> m_tokenCache;
    std::unordered_map<std::string, std::string> m_sessionCache;

    // Helper methods
    bool generateECCKeyPair();
    bool hashPassword(const std::string& password, std::vector<uint8_t>& salt, std::vector<uint8_t>& hash);
    bool verifyPassword(const std::string& password, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& hash);
    std::string generateToken(const std::string& userId, const std::string& username);
    bool validateToken(const std::string& token, std::string& userId, std::string& username);
    std::string generateUserId();
    std::string generateSessionId();
    int64_t getCurrentTimestamp();
    bool isTokenExpired(int64_t tokenTimestamp) const;

    // File I/O helpers
    bool saveUserData(const std::string& userId, const std::string& username,
                     const std::vector<uint8_t>& salt, const std::vector<uint8_t>& hash);
    bool loadUserData(const std::string& username, std::string& userId,
                     std::vector<uint8_t>& salt, std::vector<uint8_t>& hash);
    std::string getUserDataFilePath(const std::string& userId) const;
    std::string getSessionDataFilePath() const;
};

} // namespace ECC
} // namespace DegenHF

#endif // __DEGEN_HF_ECC_AUTH_H__