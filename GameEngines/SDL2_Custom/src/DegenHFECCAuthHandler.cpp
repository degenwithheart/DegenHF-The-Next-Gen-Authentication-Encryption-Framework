#include "DegenHFECCAuthHandler.hpp"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <nlohmann/json.hpp>

namespace DegenHF {

namespace fs = std::filesystem;

// Base64 encoding/decoding tables
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

// Constructor and Destructor
ECCAuthHandler::ECCAuthHandler(const AuthConfig& config)
    : config_(config) {
}

ECCAuthHandler::~ECCAuthHandler() {
    shutdown();
}

// Initialization
bool ECCAuthHandler::initialize() {
    if (initialized_) {
        return true;
    }

    try {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // Load existing data
        if (!loadAuthData()) {
            // Create new data files if they don't exist
            saveAuthData();
        }

        // Initialize cache if enabled
        if (config_.enableCaching) {
            initializeCache();
        }

        initialized_ = true;
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

void ECCAuthHandler::shutdown() {
    if (!initialized_) {
        return;
    }

    // Save data before shutdown
    saveAuthData();

    // Clear sensitive data
    currentUserId_.clear();
    currentUsername_.clear();
    currentKeyPair_.reset();

    // Clear caches
    cleanupCache();

    initialized_ = false;
}

// User Management
AuthResult ECCAuthHandler::registerUser(const std::string& username, const std::string& password) {
    if (!initialized_) {
        return AuthResult(false, "Authentication handler not initialized");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Validate input
    if (username.empty() || password.empty()) {
        return AuthResult(false, "Username and password cannot be empty");
    }

    if (username.length() < 3 || password.length() < 6) {
        return AuthResult(false, "Username must be at least 3 characters, password at least 6 characters");
    }

    // Check if user already exists
    for (const auto& [id, user] : users_) {
        if (user.username == username) {
            return AuthResult(false, "Username already exists");
        }
    }

    try {
        // Generate user ID
        std::string userId = generateUserId();

        // Generate salt
        std::vector<uint8_t> salt = generateSalt();

        // Hash password
        std::vector<uint8_t> passwordHash = hashPassword(password, salt, config_.hashIterations);

        // Generate ECC key pair
        ECCKeyPair keyPair = generateECCKeyPair();

        // Create user data
        UserData userData;
        userData.userId = userId;
        userData.username = username;
        userData.passwordHash = passwordHash;
        userData.salt = salt;
        userData.keyPair = keyPair;
        userData.createdAt = std::chrono::system_clock::now();
        userData.lastLogin = userData.createdAt;

        // Store user
        users_[userId] = userData;

        // Save data
        if (!saveAuthData()) {
            return AuthResult(false, "Failed to save user data");
        }

        AuthResult result(true);
        result.userId = userId;
        result.username = username;
        return result;

    } catch (const std::exception& e) {
        return AuthResult(false, std::string("Registration failed: ") + e.what());
    }
}

AuthResult ECCAuthHandler::authenticateUser(const std::string& username, const std::string& password) {
    if (!initialized_) {
        return AuthResult(false, "Authentication handler not initialized");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Validate input
    if (username.empty() || password.empty()) {
        return AuthResult(false, "Username and password cannot be empty");
    }

    // Find user
    UserData* userData = nullptr;
    std::string userId;
    for (auto& [id, user] : users_) {
        if (user.username == username) {
            userData = &user;
            userId = id;
            break;
        }
    }

    if (!userData) {
        return AuthResult(false, "User not found");
    }

    // Verify password
    if (!verifyPassword(password, userData->passwordHash, userData->salt, config_.hashIterations)) {
        return AuthResult(false, "Invalid password");
    }

    try {
        // Update last login
        userData->lastLogin = std::chrono::system_clock::now();

        // Set current user
        currentUserId_ = userId;
        currentUsername_ = username;
        currentKeyPair_ = userData->keyPair;

        // Create token
        auto tokenOpt = createToken(userId, username);
        if (!tokenOpt) {
            return AuthResult(false, "Failed to create authentication token");
        }

        // Create session
        std::string sessionId = createSession(userId);

        // Save data
        saveAuthData();

        AuthResult result(true);
        result.userId = userId;
        result.username = username;
        result.token = encodeToken(*tokenOpt);
        result.sessionId = sessionId;
        return result;

    } catch (const std::exception& e) {
        return AuthResult(false, std::string("Authentication failed: ") + e.what());
    }
}

void ECCAuthHandler::logout() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Clear current user
    currentUserId_.clear();
    currentUsername_.clear();
    currentKeyPair_.reset();

    // Note: We don't clear sessions/tokens here as they might be used elsewhere
    // They will be cleaned up by cleanupExpiredSessions()
}

// Token Management
std::optional<AuthToken> ECCAuthHandler::verifyToken(const std::string& token) {
    if (!initialized_) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Check cache first
    if (config_.enableCaching) {
        auto cached = getCachedToken(token);
        if (cached) {
            return cached;
        }
    }

    // Decode token
    auto decodedToken = decodeToken(token);
    if (!decodedToken) {
        return std::nullopt;
    }

    // Check if token is expired
    if (decodedToken->isExpired()) {
        invalidateToken(decodedToken->tokenId);
        return std::nullopt;
    }

    // Verify signature
    std::vector<uint8_t> tokenData = std::vector<uint8_t>(token.begin(), token.end() - 86); // Remove signature part
    UserData* userData = nullptr;
    for (auto& [id, user] : users_) {
        if (user.userId == decodedToken->userId) {
            userData = &user;
            break;
        }
    }

    if (!userData) {
        return std::nullopt;
    }

    ECDSASignature sig;
    sig.r = std::vector<uint8_t>(decodedToken->signature.begin(), decodedToken->signature.begin() + 32);
    sig.s = std::vector<uint8_t>(decodedToken->signature.begin() + 32, decodedToken->signature.end());

    if (!verifySignature(tokenData, sig, userData->keyPair.publicKey)) {
        return std::nullopt;
    }

    // Cache valid token
    if (config_.enableCaching) {
        cacheToken(*decodedToken);
    }

    return decodedToken;
}

std::optional<AuthToken> ECCAuthHandler::createToken(const std::string& userId, const std::string& username) {
    try {
        AuthToken token;
        token.tokenId = generateTokenId();
        token.userId = userId;
        token.username = username;
        token.issuedAt = std::chrono::system_clock::now();
        token.expiresAt = token.issuedAt + std::chrono::hours(config_.tokenExpiryHours);

        // Create token data for signing
        std::string tokenData = userId + username + std::to_string(getCurrentTimestamp());
        std::vector<uint8_t> data(tokenData.begin(), tokenData.end());

        // Sign token
        if (!currentKeyPair_) {
            return std::nullopt;
        }

        ECDSASignature sig = signData(data, *currentKeyPair_);
        token.signature.reserve(sig.r.size() + sig.s.size());
        token.signature.insert(token.signature.end(), sig.r.begin(), sig.r.end());
        token.signature.insert(token.signature.end(), sig.s.begin(), sig.s.end());

        // Store active token
        activeTokens_[token.tokenId] = token;

        return token;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool ECCAuthHandler::invalidateToken(const std::string& tokenId) {
    std::lock_guard<std::mutex> lock(mutex_);

    activeTokens_.erase(tokenId);
    if (config_.enableCaching) {
        removeCachedToken(tokenId);
    }
    return true;
}

// Session Management
std::string ECCAuthHandler::createSession(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);

    UserSession session;
    session.sessionId = generateSessionId();
    session.userId = userId;

    // Find username
    for (const auto& [id, user] : users_) {
        if (user.userId == userId) {
            session.username = user.username;
            break;
        }
    }

    session.createdAt = std::chrono::system_clock::now();
    session.lastActivity = session.createdAt;
    session.isActive = true;

    sessions_[session.sessionId] = session;
    return session.sessionId;
}

std::optional<UserSession> ECCAuthHandler::getSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return std::nullopt;
    }

    UserSession& session = it->second;
    if (!session.isActive || session.isExpired()) {
        sessions_.erase(it);
        return std::nullopt;
    }

    // Update last activity
    session.lastActivity = std::chrono::system_clock::now();
    return session;
}

bool ECCAuthHandler::invalidateSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        it->second.isActive = false;
        return true;
    }
    return false;
}

void ECCAuthHandler::cleanupExpiredSessions() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (!it->second.isActive || it->second.isExpired()) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

// State Queries
bool ECCAuthHandler::isUserLoggedIn() const {
    return !currentUserId_.empty();
}

std::string ECCAuthHandler::getCurrentUserId() const {
    return currentUserId_;
}

std::string ECCAuthHandler::getCurrentUsername() const {
    return currentUsername_;
}

// Data Persistence
bool ECCAuthHandler::saveAuthData() {
    try {
        // Save user data
        if (!saveUserData(users_)) {
            return false;
        }

        // Save session data
        if (!saveSessionData(sessions_)) {
            return false;
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ECCAuthHandler::loadAuthData() {
    try {
        // Load user data
        std::unordered_map<std::string, UserData> loadedUsers;
        if (!loadUserData(loadedUsers)) {
            return false;
        }
        users_ = std::move(loadedUsers);

        // Load session data
        std::unordered_map<std::string, UserSession> loadedSessions;
        if (!loadSessionData(loadedSessions)) {
            return false;
        }
        sessions_ = std::move(loadedSessions);

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// Configuration
void ECCAuthHandler::updateConfig(const AuthConfig& newConfig) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = newConfig;

    if (config_.enableCaching) {
        initializeCache();
    } else {
        cleanupCache();
    }
}

// Core ECC Operations
ECCKeyPair ECCAuthHandler::generateECCKeyPair() {
    ECCKeyPair keyPair;

    // Generate EC key pair using OpenSSL
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        throw std::runtime_error("Failed to create EC key");
    }

    if (!EC_KEY_generate_key(ecKey)) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to generate EC key pair");
    }

    // Extract private key
    const BIGNUM* privKey = EC_KEY_get0_private_key(ecKey);
    if (privKey) {
        int privLen = BN_num_bytes(privKey);
        keyPair.privateKey.resize(privLen);
        BN_bn2bin(privKey, keyPair.privateKey.data());
    }

    // Extract public key
    const EC_POINT* pubPoint = EC_KEY_get0_public_key(ecKey);
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    if (pubPoint && group) {
        int pubLen = EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_COMPRESSED,
                                       nullptr, 0, nullptr);
        if (pubLen > 0) {
            keyPair.publicKey.resize(pubLen);
            EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_COMPRESSED,
                             keyPair.publicKey.data(), pubLen, nullptr);
        }
    }

    EC_KEY_free(ecKey);
    return keyPair;
}

ECDSASignature ECCAuthHandler::signData(const std::vector<uint8_t>& data, const ECCKeyPair& keyPair) {
    ECDSASignature signature;

    // Create EC key from private key
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        throw std::runtime_error("Failed to create EC key for signing");
    }

    BIGNUM* privBN = BN_bin2bn(keyPair.privateKey.data(), keyPair.privateKey.size(), nullptr);
    if (!privBN || !EC_KEY_set_private_key(ecKey, privBN)) {
        BN_free(privBN);
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to set private key");
    }
    BN_free(privBN);

    // Compute SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);

    // Sign hash
    ECDSA_SIG* ecdsaSig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ecKey);
    if (!ecdsaSig) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to sign data");
    }

    // Extract r and s
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(ecdsaSig, &r, &s);

    if (r && s) {
        int rLen = BN_num_bytes(r);
        int sLen = BN_num_bytes(s);

        signature.r.resize(rLen);
        signature.s.resize(sLen);

        BN_bn2bin(r, signature.r.data());
        BN_bn2bin(s, signature.s.data());
    }

    ECDSA_SIG_free(ecdsaSig);
    EC_KEY_free(ecKey);

    return signature;
}

bool ECCAuthHandler::verifySignature(const std::vector<uint8_t>& data,
                                   const ECDSASignature& signature,
                                   const std::vector<uint8_t>& publicKey) {
    // Create EC key from public key
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        return false;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* pubPoint = EC_POINT_new(group);
    if (!pubPoint || !EC_POINT_oct2point(group, pubPoint, publicKey.data(), publicKey.size(), nullptr)) {
        EC_POINT_free(pubPoint);
        EC_KEY_free(ecKey);
        return false;
    }

    if (!EC_KEY_set_public_key(ecKey, pubPoint)) {
        EC_POINT_free(pubPoint);
        EC_KEY_free(ecKey);
        return false;
    }
    EC_POINT_free(pubPoint);

    // Compute SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);

    // Create ECDSA signature
    BIGNUM* rBN = BN_bin2bn(signature.r.data(), signature.r.size(), nullptr);
    BIGNUM* sBN = BN_bin2bn(signature.s.data(), signature.s.size(), nullptr);
    ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();
    if (!rBN || !sBN || !ecdsaSig || !ECDSA_SIG_set0(ecdsaSig, rBN, sBN)) {
        BN_free(rBN);
        BN_free(sBN);
        ECDSA_SIG_free(ecdsaSig);
        EC_KEY_free(ecKey);
        return false;
    }

    // Verify signature
    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, ecdsaSig, ecKey);

    ECDSA_SIG_free(ecdsaSig);
    EC_KEY_free(ecKey);

    return result == 1;
}

// Password Hashing
std::vector<uint8_t> ECCAuthHandler::hashPassword(const std::string& password,
                                                const std::vector<uint8_t>& salt,
                                                int iterations) {
    std::vector<uint8_t> hash(HASH_SIZE);

    // Use PBKDF2 with SHA256
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          iterations, EVP_sha256(),
                          hash.size(), hash.data())) {
        throw std::runtime_error("Password hashing failed");
    }

    return hash;
}

bool ECCAuthHandler::verifyPassword(const std::string& password,
                                  const std::vector<uint8_t>& hash,
                                  const std::vector<uint8_t>& salt,
                                  int iterations) {
    std::vector<uint8_t> computedHash = hashPassword(password, salt, iterations);
    return computedHash == hash;
}

// Token Operations
std::string ECCAuthHandler::encodeToken(const AuthToken& token) {
    // Simple base64 encoding of token data + signature
    std::string data = token.tokenId + "|" + token.userId + "|" + token.username + "|" +
                      std::to_string(getCurrentTimestamp()) + "|" +
                      std::to_string(config_.tokenExpiryHours);

    std::string fullToken = base64Encode(std::vector<uint8_t>(data.begin(), data.end())) + "." +
                           base64Encode(token.signature);

    return fullToken;
}

std::optional<AuthToken> ECCAuthHandler::decodeToken(const std::string& tokenString) {
    try {
        size_t dotPos = tokenString.find('.');
        if (dotPos == std::string::npos) {
            return std::nullopt;
        }

        std::string dataPart = tokenString.substr(0, dotPos);
        std::string sigPart = tokenString.substr(dotPos + 1);

        std::vector<uint8_t> data = base64Decode(dataPart);
        std::vector<uint8_t> signature = base64Decode(sigPart);

        std::string dataStr(data.begin(), data.end());
        size_t pos = 0;
        size_t nextPos;

        // Parse token data
        AuthToken token;

        nextPos = dataStr.find('|', pos);
        if (nextPos == std::string::npos) return std::nullopt;
        token.tokenId = dataStr.substr(pos, nextPos - pos);
        pos = nextPos + 1;

        nextPos = dataStr.find('|', pos);
        if (nextPos == std::string::npos) return std::nullopt;
        token.userId = dataStr.substr(pos, nextPos - pos);
        pos = nextPos + 1;

        nextPos = dataStr.find('|', pos);
        if (nextPos == std::string::npos) return std::nullopt;
        token.username = dataStr.substr(pos, nextPos - pos);
        pos = nextPos + 1;

        nextPos = dataStr.find('|', pos);
        if (nextPos == std::string::npos) return std::nullopt;
        uint64_t issued = std::stoull(dataStr.substr(pos, nextPos - pos));
        token.issuedAt = std::chrono::system_clock::time_point(std::chrono::seconds(issued));
        pos = nextPos + 1;

        int expiryHours = std::stoi(dataStr.substr(pos));
        token.expiresAt = token.issuedAt + std::chrono::hours(expiryHours);
        token.signature = signature;

        return token;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// Data Storage
std::string ECCAuthHandler::getUserDataFilePath() const {
    return config_.userDataPath + "/users.json";
}

std::string ECCAuthHandler::getSessionDataFilePath() const {
    return config_.userDataPath + "/sessions.json";
}

bool ECCAuthHandler::saveUserData(const std::unordered_map<std::string, UserData>& users) {
    try {
        // Create directory if it doesn't exist
        fs::create_directories(config_.userDataPath);

        nlohmann::json jsonData;
        for (const auto& [userId, user] : users) {
            nlohmann::json userJson;
            userJson["userId"] = user.userId;
            userJson["username"] = user.username;
            userJson["passwordHash"] = base64Encode(user.passwordHash);
            userJson["salt"] = base64Encode(user.salt);
            userJson["privateKey"] = base64Encode(user.keyPair.privateKey);
            userJson["publicKey"] = base64Encode(user.keyPair.publicKey);
            userJson["createdAt"] = std::chrono::duration_cast<std::chrono::seconds>(
                user.createdAt.time_since_epoch()).count();
            userJson["lastLogin"] = std::chrono::duration_cast<std::chrono::seconds>(
                user.lastLogin.time_since_epoch()).count();

            jsonData[userId] = userJson;
        }

        std::ofstream file(getUserDataFilePath());
        if (!file.is_open()) {
            return false;
        }

        file << jsonData.dump(2);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ECCAuthHandler::loadUserData(std::unordered_map<std::string, UserData>& users) {
    try {
        std::ifstream file(getUserDataFilePath());
        if (!file.is_open()) {
            return true; // File doesn't exist yet, not an error
        }

        nlohmann::json jsonData;
        file >> jsonData;

        for (const auto& [userId, userJson] : jsonData.items()) {
            UserData user;
            user.userId = userJson["userId"];
            user.username = userJson["username"];
            user.passwordHash = base64Decode(userJson["passwordHash"]);
            user.salt = base64Decode(userJson["salt"]);
            user.keyPair.privateKey = base64Decode(userJson["privateKey"]);
            user.keyPair.publicKey = base64Decode(userJson["publicKey"]);
            user.createdAt = std::chrono::system_clock::time_point(
                std::chrono::seconds(userJson["createdAt"]));
            user.lastLogin = std::chrono::system_clock::time_point(
                std::chrono::seconds(userJson["lastLogin"]));

            users[userId] = user;
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ECCAuthHandler::saveSessionData(const std::unordered_map<std::string, UserSession>& sessions) {
    try {
        nlohmann::json jsonData;
        for (const auto& [sessionId, session] : sessions) {
            nlohmann::json sessionJson;
            sessionJson["sessionId"] = session.sessionId;
            sessionJson["userId"] = session.userId;
            sessionJson["username"] = session.username;
            sessionJson["createdAt"] = std::chrono::duration_cast<std::chrono::seconds>(
                session.createdAt.time_since_epoch()).count();
            sessionJson["lastActivity"] = std::chrono::duration_cast<std::chrono::seconds>(
                session.lastActivity.time_since_epoch()).count();
            sessionJson["isActive"] = session.isActive;

            jsonData[sessionId] = sessionJson;
        }

        std::ofstream file(getSessionDataFilePath());
        if (!file.is_open()) {
            return false;
        }

        file << jsonData.dump(2);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ECCAuthHandler::loadSessionData(std::unordered_map<std::string, UserSession>& sessions) {
    try {
        std::ifstream file(getSessionDataFilePath());
        if (!file.is_open()) {
            return true; // File doesn't exist yet, not an error
        }

        nlohmann::json jsonData;
        file >> jsonData;

        for (const auto& [sessionId, sessionJson] : jsonData.items()) {
            UserSession session;
            session.sessionId = sessionJson["sessionId"];
            session.userId = sessionJson["userId"];
            session.username = sessionJson["username"];
            session.createdAt = std::chrono::system_clock::time_point(
                std::chrono::seconds(sessionJson["createdAt"]));
            session.lastActivity = std::chrono::system_clock::time_point(
                std::chrono::seconds(sessionJson["lastActivity"]));
            session.isActive = sessionJson["isActive"];

            sessions[sessionId] = session;
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// Cache Management
void ECCAuthHandler::initializeCache() {
    tokenCache_.clear();
}

void ECCAuthHandler::cleanupCache() {
    tokenCache_.clear();
}

std::optional<AuthToken> ECCAuthHandler::getCachedToken(const std::string& tokenId) {
    auto it = tokenCache_.find(tokenId);
    if (it == tokenCache_.end()) {
        return std::nullopt;
    }

    if (std::chrono::system_clock::now() > it->second.expiresAt) {
        tokenCache_.erase(it);
        return std::nullopt;
    }

    return it->second.token;
}

void ECCAuthHandler::cacheToken(const AuthToken& token) {
    if (tokenCache_.size() >= config_.maxCacheSize) {
        // Simple LRU: remove oldest entry
        auto oldest = tokenCache_.begin();
        for (auto it = tokenCache_.begin(); it != tokenCache_.end(); ++it) {
            if (it->second.expiresAt < oldest->second.expiresAt) {
                oldest = it;
            }
        }
        tokenCache_.erase(oldest);
    }

    CacheEntry entry;
    entry.token = token;
    entry.expiresAt = std::chrono::system_clock::now() + std::chrono::minutes(config_.cacheExpiryMinutes);

    tokenCache_[token.tokenId] = entry;
}

void ECCAuthHandler::removeCachedToken(const std::string& tokenId) {
    tokenCache_.erase(tokenId);
}

// Utility Functions
std::string ECCAuthHandler::generateUserId() {
    return "user_" + std::to_string(getCurrentTimestamp()) + "_" + std::to_string(rand());
}

std::string ECCAuthHandler::generateTokenId() {
    return "token_" + std::to_string(getCurrentTimestamp()) + "_" + std::to_string(rand());
}

std::string ECCAuthHandler::generateSessionId() {
    return "session_" + std::to_string(getCurrentTimestamp()) + "_" + std::to_string(rand());
}

std::vector<uint8_t> ECCAuthHandler::generateSalt(size_t length) {
    std::vector<uint8_t> salt(length);
    if (!RAND_bytes(salt.data(), salt.size())) {
        throw std::runtime_error("Failed to generate salt");
    }
    return salt;
}

std::string ECCAuthHandler::base64Encode(const std::vector<uint8_t>& data) {
    std::string encoded;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t idx = 0; idx < data.size(); ++idx) {
        char_array_3[i++] = data[idx];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        while((i++ < 3))
            encoded += '=';
    }

    return encoded;
}

std::vector<uint8_t> ECCAuthHandler::base64Decode(const std::string& encoded) {
    size_t in_len = encoded.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<uint8_t> decoded;

    while (in_len-- && (encoded[in_] != '=') && is_base64(encoded[in_])) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                decoded.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) decoded.push_back(char_array_3[j]);
    }

    return decoded;
}

std::string ECCAuthHandler::toHexString(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> ECCAuthHandler::fromHexString(const std::string& hex) {
    std::vector<uint8_t> data;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        data.push_back(byte);
    }
    return data;
}

uint64_t ECCAuthHandler::getCurrentTimestamp() const {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace DegenHF