#ifndef __DEGEN_HF_COCOS2DX_EXTENSION_H__
#define __DEGEN_HF_COCOS2DX_EXTENSION_H__

#include "ECCAuthHandler.h"
#include <cocos2d.h>
#include <functional>

namespace DegenHF {
namespace Cocos2dx {

/**
 * @brief Cocos2d-x extension for DegenHF ECC authentication
 *
 * Provides easy-to-use authentication integration for Cocos2d-x games
 * with automatic scene management and UI callbacks.
 */
class AuthExtension : public cocos2d::Ref {
public:
    /**
     * @brief Authentication callback types
     */
    using AuthCallback = std::function<void(bool success, const std::string& message)>;
    using RegisterCallback = std::function<void(bool success, const std::string& userId, const std::string& message)>;
    using LoginCallback = std::function<void(bool success, const std::string& token, const std::string& userId, const std::string& username, const std::string& message)>;

    /**
     * @brief Get singleton instance
     * @return AuthExtension instance
     */
    static AuthExtension* getInstance();

    /**
     * @brief Initialize the extension
     * @param config Authentication configuration
     * @return true if initialization successful
     */
    bool init(const ECC::AuthHandler::Config& config = ECC::AuthHandler::Config());

    /**
     * @brief Register a new user
     * @param username Username for registration
     * @param password Password for registration
     * @param callback Callback function for result
     */
    void registerUser(const std::string& username, const std::string& password, RegisterCallback callback = nullptr);

    /**
     * @brief Login user
     * @param username Username for login
     * @param password Password for login
     * @param callback Callback function for result
     */
    void loginUser(const std::string& username, const std::string& password, LoginCallback callback = nullptr);

    /**
     * @brief Logout current user
     * @param callback Callback function for result
     */
    void logoutUser(AuthCallback callback = nullptr);

    /**
     * @brief Check if user is logged in
     * @return true if user is logged in
     */
    bool isLoggedIn() const;

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
     * @brief Verify authentication token
     * @param token Token to verify
     * @param callback Callback function for result
     */
    void verifyToken(const std::string& token, AuthCallback callback = nullptr);

    /**
     * @brief Create a secure session
     * @param callback Callback function with session ID
     */
    void createSession(std::function<void(const std::string& sessionId)> callback = nullptr);

    /**
     * @brief Get session information
     * @param sessionId Session ID to query
     * @param callback Callback function with user info
     */
    void getSessionInfo(const std::string& sessionId,
                       std::function<void(bool valid, const std::string& userId, const std::string& username)> callback = nullptr);

    /**
     * @brief Save authentication state
     */
    void saveAuthState();

    /**
     * @brief Load authentication state
     */
    void loadAuthState();

    /**
     * @brief Get the underlying auth handler
     * @return Pointer to ECC auth handler
     */
    ECC::AuthHandler* getAuthHandler() { return m_authHandler.get(); }

private:
    AuthExtension();
    ~AuthExtension();

    std::unique_ptr<ECC::AuthHandler> m_authHandler;
    bool m_initialized;

    // Prevent copying
    AuthExtension(const AuthExtension&) = delete;
    AuthExtension& operator=(const AuthExtension&) = delete;

    // Helper methods
    void runCallbackOnMainThread(std::function<void()> callback);
};

} // namespace Cocos2dx
} // namespace DegenHF

#endif // __DEGEN_HF_COCOS2DX_EXTENSION_H__