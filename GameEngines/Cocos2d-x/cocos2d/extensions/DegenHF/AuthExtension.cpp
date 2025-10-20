#include "AuthExtension.h"
#include <cocos2d.h>

USING_NS_CC;

namespace DegenHF {
namespace Cocos2dx {

static AuthExtension* s_instance = nullptr;

AuthExtension* AuthExtension::getInstance() {
    if (!s_instance) {
        s_instance = new AuthExtension();
    }
    return s_instance;
}

AuthExtension::AuthExtension()
    : m_authHandler(nullptr)
    , m_initialized(false) {
}

AuthExtension::~AuthExtension() {
    if (m_authHandler) {
        m_authHandler->saveAuthData();
    }
}

bool AuthExtension::init(const ECC::AuthHandler::Config& config) {
    if (m_initialized) {
        return true;
    }

    m_authHandler = std::make_unique<ECC::AuthHandler>(config);
    if (!m_authHandler->initialize()) {
        CCLOG("Failed to initialize ECC Auth Handler");
        return false;
    }

    m_initialized = true;
    CCLOG("DegenHF Cocos2d-x Auth Extension initialized successfully");
    return true;
}

void AuthExtension::registerUser(const std::string& username, const std::string& password, RegisterCallback callback) {
    if (!m_initialized || !m_authHandler) {
        if (callback) {
            runCallbackOnMainThread([callback]() {
                callback(false, "", "Extension not initialized");
            });
        }
        return;
    }

    // Perform registration on background thread
    Director::getInstance()->getScheduler()->performFunctionInCocosThread([this, username, password, callback]() {
        auto result = m_authHandler->registerUser(username, password);

        if (callback) {
            runCallbackOnMainThread([callback, result]() {
                callback(result.success, result.userId, result.errorMessage);
            });
        }
    });
}

void AuthExtension::loginUser(const std::string& username, const std::string& password, LoginCallback callback) {
    if (!m_initialized || !m_authHandler) {
        if (callback) {
            runCallbackOnMainThread([callback]() {
                callback(false, "", "", "", "Extension not initialized");
            });
        }
        return;
    }

    // Perform login on background thread
    Director::getInstance()->getScheduler()->performFunctionInCocosThread([this, username, password, callback]() {
        auto result = m_authHandler->authenticateUser(username, password);

        if (callback) {
            runCallbackOnMainThread([callback, result]() {
                callback(result.success, result.token, result.userId, result.username, result.errorMessage);
            });
        }
    });
}

void AuthExtension::logoutUser(AuthCallback callback) {
    if (!m_initialized || !m_authHandler) {
        if (callback) {
            runCallbackOnMainThread([callback]() {
                callback(false, "Extension not initialized");
            });
        }
        return;
    }

    m_authHandler->logout();
    m_authHandler->saveAuthData();

    if (callback) {
        runCallbackOnMainThread([callback]() {
            callback(true, "Logged out successfully");
        });
    }
}

bool AuthExtension::isLoggedIn() const {
    if (!m_initialized || !m_authHandler) {
        return false;
    }
    return m_authHandler->isUserLoggedIn();
}

std::string AuthExtension::getCurrentUserId() const {
    if (!m_initialized || !m_authHandler) {
        return "";
    }
    return m_authHandler->getCurrentUserId();
}

std::string AuthExtension::getCurrentUsername() const {
    if (!m_initialized || !m_authHandler) {
        return "";
    }
    return m_authHandler->getCurrentUsername();
}

void AuthExtension::verifyToken(const std::string& token, AuthCallback callback) {
    if (!m_initialized || !m_authHandler) {
        if (callback) {
            runCallbackOnMainThread([callback]() {
                callback(false, "Extension not initialized");
            });
        }
        return;
    }

    // Perform verification on background thread
    Director::getInstance()->getScheduler()->performFunctionInCocosThread([this, token, callback]() {
        auto result = m_authHandler->verifyToken(token);

        if (callback) {
            runCallbackOnMainThread([callback, result]() {
                callback(result.valid, result.valid ? "Token valid" : result.errorMessage);
            });
        }
    });
}

void AuthExtension::createSession(std::function<void(const std::string& sessionId)> callback) {
    if (!m_initialized || !m_authHandler) {
        if (callback) {
            runCallbackOnMainThread([callback]() {
                callback("");
            });
        }
        return;
    }

    std::string userId = m_authHandler->getCurrentUserId();
    if (userId.empty()) {
        if (callback) {
            runCallbackOnMainThread([callback]() {
                callback("");
            });
        }
        return;
    }

    std::string sessionId = m_authHandler->createSession(userId);

    if (callback) {
        runCallbackOnMainThread([callback, sessionId]() {
            callback(sessionId);
        });
    }
}

void AuthExtension::getSessionInfo(const std::string& sessionId,
                                  std::function<void(bool valid, const std::string& userId, const std::string& username)> callback) {
    if (!m_initialized || !m_authHandler) {
        if (callback) {
            runCallbackOnMainThread([callback]() {
                callback(false, "", "");
            });
        }
        return;
    }

    std::string userId, username;
    bool valid = m_authHandler->getSession(sessionId, userId, username);

    if (callback) {
        runCallbackOnMainThread([callback, valid, userId, username]() {
            callback(valid, userId, username);
        });
    }
}

void AuthExtension::saveAuthState() {
    if (m_initialized && m_authHandler) {
        m_authHandler->saveAuthData();
    }
}

void AuthExtension::loadAuthState() {
    if (m_initialized && m_authHandler) {
        m_authHandler->loadAuthData();
    }
}

void AuthExtension::runCallbackOnMainThread(std::function<void()> callback) {
    if (callback) {
        Director::getInstance()->getScheduler()->performFunctionInCocosThread(callback);
    }
}

} // namespace Cocos2dx
} // namespace DegenHF