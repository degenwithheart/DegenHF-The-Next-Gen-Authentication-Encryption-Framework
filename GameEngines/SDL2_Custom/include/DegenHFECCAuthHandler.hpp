#ifndef DEGENHF_ECC_AUTH_HANDLER_HPP
#define DEGENHF_ECC_AUTH_HANDLER_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <optional>

namespace DegenHF {

// Forward declarations
struct ECCKeyPair;
struct ECDSASignature;
struct AuthToken;
struct UserSession;
struct AuthResult;

// Configuration structure
struct AuthConfig {
    int hashIterations = 10000;
    int tokenExpiryHours = 24;
    int cacheExpiryMinutes = 5;
    std::string userDataPath = "DegenHFAuth";
    bool enableCaching = true;
    size_t maxCacheSize = 1000;
};

// ECC Key Pair structure
struct ECCKeyPair {
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> publicKey;

    ECCKeyPair() = default;
    ECCKeyPair(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& pub)
        : privateKey(priv), publicKey(pub) {}
};

// ECDSA Signature structure
struct ECDSASignature {
    std::vector<uint8_t> r;
    std::vector<uint8_t> s;

    ECDSASignature() = default;
    ECDSASignature(const std::vector<uint8_t>& r_val, const std::vector<uint8_t>& s_val)
        : r(r_val), s(s_val) {}
};

// Authentication Token structure
struct AuthToken {
    std::string tokenId;
    std::string userId;
    std::string username;
    std::chrono::system_clock::time_point issuedAt;
    std::chrono::system_clock::time_point expiresAt;
    std::vector<uint8_t> signature;

    AuthToken() = default;
    bool isExpired() const {
        return std::chrono::system_clock::now() > expiresAt;
    }
};

// User Session structure
struct UserSession {
    std::string sessionId;
    std::string userId;
    std::string username;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastActivity;
    bool isActive = true;

    UserSession() = default;
    bool isExpired(int maxInactiveMinutes = 30) const {
        auto now = std::chrono::system_clock::now();
        auto inactiveDuration = std::chrono::duration_cast<std::chrono::minutes>(
            now - lastActivity);
        return inactiveDuration.count() > maxInactiveMinutes;
    }
};

// Authentication Result structure
struct AuthResult {
    bool success = false;
    std::string userId;
    std::string username;
    std::string token;
    std::string sessionId;
    std::string errorMessage;

    AuthResult() = default;
    AuthResult(bool succ, const std::string& msg = "")
        : success(succ), errorMessage(msg) {}
};

// User Data structure for persistence
struct UserData {
    std::string userId;
    std::string username;
    std::vector<uint8_t> passwordHash;
    std::vector<uint8_t> salt;
    ECCKeyPair keyPair;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastLogin;

    UserData() = default;
};

// Main ECC Authentication Handler class
class ECCAuthHandler {
public:
    // Constructor and Destructor
    explicit ECCAuthHandler(const AuthConfig& config = AuthConfig());
    ~ECCAuthHandler();

    // Initialization
    bool initialize();
    void shutdown();

    // User Management
    AuthResult registerUser(const std::string& username, const std::string& password);
    AuthResult authenticateUser(const std::string& username, const std::string& password);
    void logout();

    // Token Management
    std::optional<AuthToken> verifyToken(const std::string& token);
    std::optional<AuthToken> createToken(const std::string& userId, const std::string& username);
    bool invalidateToken(const std::string& tokenId);

    // Session Management
    std::string createSession(const std::string& userId);
    std::optional<UserSession> getSession(const std::string& sessionId);
    bool invalidateSession(const std::string& sessionId);
    void cleanupExpiredSessions();

    // State Queries
    bool isUserLoggedIn() const;
    std::string getCurrentUserId() const;
    std::string getCurrentUsername() const;

    // Data Persistence
    bool saveAuthData();
    bool loadAuthData();

    // Utility Functions
    static std::string generateUserId();
    static std::string generateTokenId();
    static std::string generateSessionId();
    static std::vector<uint8_t> generateSalt(size_t length = 32);

    // Configuration
    const AuthConfig& getConfig() const { return config_; }
    void updateConfig(const AuthConfig& newConfig);

private:
    // Core ECC Operations
    ECCKeyPair generateECCKeyPair();
    ECDSASignature signData(const std::vector<uint8_t>& data, const ECCKeyPair& keyPair);
    bool verifySignature(const std::vector<uint8_t>& data,
                        const ECDSASignature& signature,
                        const std::vector<uint8_t>& publicKey);

    // Password Hashing
    std::vector<uint8_t> hashPassword(const std::string& password,
                                    const std::vector<uint8_t>& salt,
                                    int iterations);
    bool verifyPassword(const std::string& password,
                       const std::vector<uint8_t>& hash,
                       const std::vector<uint8_t>& salt,
                       int iterations);

    // Token Operations
    std::string encodeToken(const AuthToken& token);
    std::optional<AuthToken> decodeToken(const std::string& tokenString);

    // Data Storage
    std::string getUserDataFilePath() const;
    std::string getSessionDataFilePath() const;
    bool saveUserData(const std::unordered_map<std::string, UserData>& users);
    bool loadUserData(std::unordered_map<std::string, UserData>& users);
    bool saveSessionData(const std::unordered_map<std::string, UserSession>& sessions);
    bool loadSessionData(std::unordered_map<std::string, UserSession>& sessions);

    // Cache Management
    void initializeCache();
    void cleanupCache();
    std::optional<AuthToken> getCachedToken(const std::string& tokenId);
    void cacheToken(const AuthToken& token);
    void removeCachedToken(const std::string& tokenId);

    // Utility Functions
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64Decode(const std::string& data);
    std::string toHexString(const std::vector<uint8_t>& data);
    std::vector<uint8_t> fromHexString(const std::string& hex);
    uint64_t getCurrentTimestamp() const;

    // Member Variables
    AuthConfig config_;
    bool initialized_ = false;

    // Current user state
    std::string currentUserId_;
    std::string currentUsername_;
    std::optional<ECCKeyPair> currentKeyPair_;

    // Data storage
    std::unordered_map<std::string, UserData> users_;
    std::unordered_map<std::string, UserSession> sessions_;
    std::unordered_map<std::string, AuthToken> activeTokens_;

    // Caching
    struct CacheEntry {
        AuthToken token;
        std::chrono::system_clock::time_point expiresAt;
    };
    std::unordered_map<std::string, CacheEntry> tokenCache_;

    // Thread safety
    mutable std::mutex mutex_;

    // Constants
    static constexpr size_t ECC_KEY_SIZE = 32; // secp256k1 key size
    static constexpr size_t SALT_SIZE = 32;
    static constexpr size_t HASH_SIZE = 32;
    static constexpr int DEFAULT_TOKEN_EXPIRY_HOURS = 24;
    static constexpr int DEFAULT_CACHE_EXPIRY_MINUTES = 5;
};

} // namespace DegenHF

#endif // DEGENHF_ECC_AUTH_HANDLER_HPP