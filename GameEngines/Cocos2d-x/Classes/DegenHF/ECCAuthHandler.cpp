#include "ECCAuthHandler.h"
#include <cocos2d.h>
#include <json/document.h>
#include <json/writer.h>
#include <json/stringbuffer.h>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

USING_NS_CC;

namespace DegenHF {
namespace ECC {

namespace {
// Helper functions for ECC operations
bool generateECCKeyPair(std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey) {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) return false;

    if (!EC_KEY_generate_key(ecKey)) {
        EC_KEY_free(ecKey);
        return false;
    }

    // Get private key
    const BIGNUM* priv = EC_KEY_get0_private_key(ecKey);
    if (!priv) {
        EC_KEY_free(ecKey);
        return false;
    }

    int privLen = BN_num_bytes(priv);
    privateKey.resize(privLen);
    BN_bn2bin(priv, privateKey.data());

    // Get public key
    const EC_POINT* pub = EC_KEY_get0_public_key(ecKey);
    if (!pub) {
        EC_KEY_free(ecKey);
        return false;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        EC_KEY_free(ecKey);
        return false;
    }

    int pubLen = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (pubLen <= 0) {
        EC_GROUP_free(group);
        EC_KEY_free(ecKey);
        return false;
    }

    publicKey.resize(pubLen);
    EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, publicKey.data(), pubLen, nullptr);

    EC_GROUP_free(group);
    EC_KEY_free(ecKey);
    return true;
}

bool hashPassword(const std::string& password, std::vector<uint8_t>& salt, std::vector<uint8_t>& hash, int iterations = 10000) {
    // Generate salt
    salt.resize(32);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        return false;
    }

    // Use PBKDF2 with SHA-256
    hash.resize(32);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         salt.data(), salt.size(),
                         iterations, EVP_sha256(),
                         hash.size(), hash.data()) != 1) {
        return false;
    }

    return true;
}

bool verifyPassword(const std::string& password, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& hash, int iterations = 10000) {
    std::vector<uint8_t> computedHash(32);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         salt.data(), salt.size(),
                         iterations, EVP_sha256(),
                         computedHash.size(), computedHash.data()) != 1) {
        return false;
    }

    return computedHash == hash;
}

std::string base64Encode(const std::vector<uint8_t>& data) {
    static const char* base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int i = 0;
    int j = 0;
    uint8_t charArray3[3];
    uint8_t charArray4[4];

    for (size_t idx = 0; idx < data.size(); ++idx) {
        charArray3[i++] = data[idx];
        if (i == 3) {
            charArray4[0] = (charArray3[0] & 0xfc) >> 2;
            charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
            charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
            charArray4[3] = charArray3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                result += base64Chars[charArray4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            charArray3[j] = '\0';
        }

        charArray4[0] = (charArray3[0] & 0xfc) >> 2;
        charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
        charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
        charArray4[3] = charArray3[2] & 0x3f;

        for (j = 0; j < i + 1; j++) {
            result += base64Chars[charArray4[j]];
        }

        while (i++ < 3) {
            result += '=';
        }
    }

    return result;
}

std::vector<uint8_t> base64Decode(const std::string& encoded) {
    static const std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    int inLen = encoded.size();
    int i = 0;
    int j = 0;
    int in = 0;
    uint8_t charArray4[4], charArray3[3];

    while (inLen-- && (encoded[in] != '=') && isalnum(encoded[in]) || (encoded[in] == '+') || (encoded[in] == '/')) {
        charArray4[i++] = encoded[in];
        in++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                charArray4[i] = base64Chars.find(charArray4[i]);
            }

            charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
            charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
            charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];

            for (i = 0; i < 3; i++) {
                result.push_back(charArray3[i]);
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            charArray4[j] = 0;
        }

        for (j = 0; j < 4; j++) {
            charArray4[j] = base64Chars.find(charArray4[j]);
        }

        charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
        charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
        charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];

        for (j = 0; j < i - 1; j++) {
            result.push_back(charArray3[j]);
        }
    }

    return result;
}

std::string generateRandomString(size_t length) {
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }

    return result;
}

int64_t getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // anonymous namespace

AuthHandler::AuthHandler(const Config& config)
    : m_config(config) {
}

AuthHandler::~AuthHandler() {
    logout();
}

bool AuthHandler::initialize() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate ECC key pair for the handler
    if (!generateECCKeyPair(m_privateKey, m_publicKey)) {
        CCLOG("Failed to generate ECC key pair");
        return false;
    }

    // Create user data directory if it doesn't exist
    std::string userDataDir = FileUtils::getInstance()->getWritablePath() + m_config.userDataPath;
    if (!FileUtils::getInstance()->createDirectory(userDataDir)) {
        CCLOG("Failed to create user data directory: %s", userDataDir.c_str());
        return false;
    }

    // Load existing authentication data
    loadAuthData();

    CCLOG("DegenHF ECC Auth Handler initialized successfully");
    return true;
}

AuthHandler::RegisterResult AuthHandler::registerUser(const std::string& username, const std::string& password) {
    RegisterResult result;

    if (username.empty() || password.empty()) {
        result.errorMessage = "Username and password cannot be empty";
        return result;
    }

    // Check if user already exists
    std::string existingUserId;
    std::vector<uint8_t> dummySalt, dummyHash;
    if (loadUserData(username, existingUserId, dummySalt, dummyHash)) {
        result.errorMessage = "User already exists";
        return result;
    }

    // Generate user ID
    result.userId = generateUserId();

    // Hash password
    std::vector<uint8_t> salt, hash;
    if (!hashPassword(password, salt, hash, m_config.hashIterations)) {
        result.errorMessage = "Failed to hash password";
        return result;
    }

    // Save user data
    if (!saveUserData(result.userId, username, salt, hash)) {
        result.errorMessage = "Failed to save user data";
        return result;
    }

    result.success = true;
    CCLOG("User registered successfully: %s", username.c_str());
    return result;
}

AuthHandler::AuthResult AuthHandler::authenticateUser(const std::string& username, const std::string& password) {
    AuthResult result;

    if (username.empty() || password.empty()) {
        result.errorMessage = "Username and password cannot be empty";
        return result;
    }

    // Load user data
    std::vector<uint8_t> salt, hash;
    if (!loadUserData(username, result.userId, salt, hash)) {
        result.errorMessage = "User not found";
        return result;
    }

    // Verify password
    if (!verifyPassword(password, salt, hash, m_config.hashIterations)) {
        result.errorMessage = "Invalid password";
        return result;
    }

    // Generate token
    result.token = generateToken(result.userId, username);
    result.username = username;
    result.success = true;

    // Set current user
    m_currentUserId = result.userId;
    m_currentUsername = username;
    m_currentToken = result.token;

    CCLOG("User authenticated successfully: %s", username.c_str());
    return result;
}

AuthHandler::VerifyResult AuthHandler::verifyToken(const std::string& token) {
    VerifyResult result;

    if (token.empty()) {
        result.errorMessage = "Token cannot be empty";
        return result;
    }

    if (validateToken(token, result.userId, result.username)) {
        result.valid = true;
    } else {
        result.errorMessage = "Invalid or expired token";
    }

    return result;
}

std::string AuthHandler::createSession(const std::string& userId) {
    std::string sessionId = generateSessionId();
    m_sessionCache[sessionId] = userId;
    return sessionId;
}

bool AuthHandler::getSession(const std::string& sessionId, std::string& userId, std::string& username) {
    auto it = m_sessionCache.find(sessionId);
    if (it == m_sessionCache.end()) {
        return false;
    }

    userId = it->second;
    // Load username from user data
    std::vector<uint8_t> dummySalt, dummyHash;
    return loadUserData("", userId, dummySalt, dummyHash, &username);
}

bool AuthHandler::isUserLoggedIn() const {
    return !m_currentUserId.empty() && !m_currentToken.empty();
}

std::string AuthHandler::getCurrentUserId() const {
    return m_currentUserId;
}

std::string AuthHandler::getCurrentUsername() const {
    return m_currentUsername;
}

void AuthHandler::logout() {
    m_currentUserId.clear();
    m_currentUsername.clear();
    m_currentToken.clear();
    m_sessionCache.clear();
    m_tokenCache.clear();
}

void AuthHandler::saveAuthData() {
    // Save session data
    std::string sessionFile = getSessionDataFilePath();
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();

    // Save current user info
    if (!m_currentUserId.empty()) {
        doc.AddMember("currentUserId", rapidjson::Value(m_currentUserId.c_str(), allocator), allocator);
        doc.AddMember("currentUsername", rapidjson::Value(m_currentUsername.c_str(), allocator), allocator);
        doc.AddMember("currentToken", rapidjson::Value(m_currentToken.c_str(), allocator), allocator);
    }

    // Save session cache
    rapidjson::Value sessions(rapidjson::kObjectType);
    for (const auto& pair : m_sessionCache) {
        sessions.AddMember(rapidjson::Value(pair.first.c_str(), allocator),
                          rapidjson::Value(pair.second.c_str(), allocator), allocator);
    }
    doc.AddMember("sessions", sessions, allocator);

    // Write to file
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    std::ofstream file(sessionFile);
    if (file.is_open()) {
        file << buffer.GetString();
        file.close();
    }
}

void AuthHandler::loadAuthData() {
    std::string sessionFile = getSessionDataFilePath();
    if (!FileUtils::getInstance()->isFileExist(sessionFile)) {
        return;
    }

    std::string content = FileUtils::getInstance()->getStringFromFile(sessionFile);
    rapidjson::Document doc;
    doc.Parse(content.c_str());

    if (doc.HasParseError() || !doc.IsObject()) {
        return;
    }

    // Load current user info
    if (doc.HasMember("currentUserId") && doc["currentUserId"].IsString()) {
        m_currentUserId = doc["currentUserId"].GetString();
    }
    if (doc.HasMember("currentUsername") && doc["currentUsername"].IsString()) {
        m_currentUsername = doc["currentUsername"].GetString();
    }
    if (doc.HasMember("currentToken") && doc["currentToken"].IsString()) {
        m_currentToken = doc["currentToken"].GetString();
    }

    // Load session cache
    if (doc.HasMember("sessions") && doc["sessions"].IsObject()) {
        const rapidjson::Value& sessions = doc["sessions"];
        for (auto it = sessions.MemberBegin(); it != sessions.MemberEnd(); ++it) {
            if (it->name.IsString() && it->value.IsString()) {
                m_sessionCache[it->name.GetString()] = it->value.GetString();
            }
        }
    }
}

// Private helper methods
bool AuthHandler::generateECCKeyPair() {
    return ::generateECCKeyPair(m_privateKey, m_publicKey);
}

bool AuthHandler::hashPassword(const std::string& password, std::vector<uint8_t>& salt, std::vector<uint8_t>& hash) {
    return ::hashPassword(password, salt, hash, m_config.hashIterations);
}

bool AuthHandler::verifyPassword(const std::string& password, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& hash) {
    return ::verifyPassword(password, salt, hash, m_config.hashIterations);
}

std::string AuthHandler::generateToken(const std::string& userId, const std::string& username) {
    // Simple JWT-like token generation (simplified for Cocos2d-x)
    int64_t timestamp = getCurrentTimestamp();
    std::string payload = userId + ":" + username + ":" + std::to_string(timestamp);
    std::string token = base64Encode(std::vector<uint8_t>(payload.begin(), payload.end()));
    m_tokenCache[token] = payload;
    return token;
}

bool AuthHandler::validateToken(const std::string& token, std::string& userId, std::string& username) {
    auto it = m_tokenCache.find(token);
    if (it == m_tokenCache.end()) {
        return false;
    }

    std::string payload = it->second;
    std::vector<uint8_t> decoded = base64Decode(payload);
    std::string decodedStr(decoded.begin(), decoded.end());

    size_t pos1 = decodedStr.find(':');
    size_t pos2 = decodedStr.find(':', pos1 + 1);
    if (pos1 == std::string::npos || pos2 == std::string::npos) {
        return false;
    }

    userId = decodedStr.substr(0, pos1);
    username = decodedStr.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string timestampStr = decodedStr.substr(pos2 + 1);
    int64_t timestamp = std::stoll(timestampStr);

    return !isTokenExpired(timestamp);
}

std::string AuthHandler::generateUserId() {
    return "user_" + generateRandomString(16);
}

std::string AuthHandler::generateSessionId() {
    return "session_" + generateRandomString(32);
}

int64_t AuthHandler::getCurrentTimestamp() {
    return ::getCurrentTimestamp();
}

bool AuthHandler::isTokenExpired(int64_t tokenTimestamp) const {
    int64_t currentTime = getCurrentTimestamp();
    int64_t expiryTime = tokenTimestamp + (m_config.tokenExpiryHours * 60 * 60 * 1000LL);
    return currentTime > expiryTime;
}

bool AuthHandler::saveUserData(const std::string& userId, const std::string& username,
                              const std::vector<uint8_t>& salt, const std::vector<uint8_t>& hash) {
    std::string filePath = getUserDataFilePath(userId);
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();

    doc.AddMember("userId", rapidjson::Value(userId.c_str(), allocator), allocator);
    doc.AddMember("username", rapidjson::Value(username.c_str(), allocator), allocator);
    doc.AddMember("salt", rapidjson::Value(base64Encode(salt).c_str(), allocator), allocator);
    doc.AddMember("hash", rapidjson::Value(base64Encode(hash).c_str(), allocator), allocator);
    doc.AddMember("created", getCurrentTimestamp(), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    std::ofstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    file << buffer.GetString();
    file.close();
    return true;
}

bool AuthHandler::loadUserData(const std::string& username, std::string& userId,
                              std::vector<uint8_t>& salt, std::vector<uint8_t>& hash, std::string* outUsername) {
    // If username is provided, we need to find the user file by username
    // This is a simplified implementation - in production, you'd want a username-to-userId mapping
    if (!username.empty()) {
        // For simplicity, assume userId is known or search through files
        // In a real implementation, you'd have a separate index file
        std::string userDataDir = FileUtils::getInstance()->getWritablePath() + m_config.userDataPath + "/";
        std::vector<std::string> files = FileUtils::getInstance()->listFiles(userDataDir);

        for (const auto& file : files) {
            if (file.find("user_") == 0) {
                std::string content = FileUtils::getInstance()->getStringFromFile(file);
                rapidjson::Document doc;
                doc.Parse(content.c_str());

                if (!doc.HasParseError() && doc.IsObject() &&
                    doc.HasMember("username") && doc["username"].IsString() &&
                    doc["username"].GetString() == username) {

                    userId = doc["userId"].GetString();
                    salt = base64Decode(doc["salt"].GetString());
                    hash = base64Decode(doc["hash"].GetString());
                    if (outUsername) *outUsername = username;
                    return true;
                }
            }
        }
        return false;
    }

    // If userId is provided directly
    std::string filePath = getUserDataFilePath(userId);
    if (!FileUtils::getInstance()->isFileExist(filePath)) {
        return false;
    }

    std::string content = FileUtils::getInstance()->getStringFromFile(filePath);
    rapidjson::Document doc;
    doc.Parse(content.c_str());

    if (doc.HasParseError() || !doc.IsObject()) {
        return false;
    }

    if (doc.HasMember("salt") && doc["salt"].IsString()) {
        salt = base64Decode(doc["salt"].GetString());
    }
    if (doc.HasMember("hash") && doc["hash"].IsString()) {
        hash = base64Decode(doc["hash"].GetString());
    }
    if (outUsername && doc.HasMember("username") && doc["username"].IsString()) {
        *outUsername = doc["username"].GetString();
    }

    return true;
}

std::string AuthHandler::getUserDataFilePath(const std::string& userId) const {
    std::string userDataDir = FileUtils::getInstance()->getWritablePath() + m_config.userDataPath + "/";
    return userDataDir + userId + ".json";
}

std::string AuthHandler::getSessionDataFilePath() const {
    std::string userDataDir = FileUtils::getInstance()->getWritablePath() + m_config.userDataPath + "/";
    return userDataDir + "session.json";
}

} // namespace ECC
} // namespace DegenHF