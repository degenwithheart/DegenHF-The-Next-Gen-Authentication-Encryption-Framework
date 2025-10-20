#include "AuthSampleScene.h"
#include <ui/CocosGUI.h>

USING_NS_CC;
using namespace ui;

Scene* AuthSampleScene::createScene() {
    return AuthSampleScene::create();
}

bool AuthSampleScene::init() {
    if (!Scene::init()) {
        return false;
    }

    // Initialize auth extension
    m_auth = DegenHF::Cocos2dx::AuthExtension::getInstance();
    DegenHF::ECC::AuthHandler::Config config;
    config.userDataPath = "DegenHFAuth";
    config.hashIterations = 10000;
    config.tokenExpiryHours = 24;

    if (!m_auth->init(config)) {
        CCLOG("Failed to initialize auth extension");
        return false;
    }

    setupUI();
    updateUI();

    return true;
}

void AuthSampleScene::setupUI() {
    auto visibleSize = Director::getInstance()->getVisibleSize();
    Vec2 origin = Director::getInstance()->getVisibleOrigin();

    // Background
    auto bg = LayerColor::create(Color4B(50, 50, 50, 255));
    this->addChild(bg);

    // Title
    auto titleLabel = Label::createWithTTF("DegenHF ECC Authentication", "fonts/Marker Felt.ttf", 32);
    titleLabel->setPosition(Vec2(origin.x + visibleSize.width / 2,
                                origin.y + visibleSize.height - 50));
    this->addChild(titleLabel);

    // Status label
    m_statusLabel = Label::createWithTTF("Not logged in", "fonts/Marker Felt.ttf", 24);
    m_statusLabel->setPosition(Vec2(origin.x + visibleSize.width / 2,
                                   origin.y + visibleSize.height - 100));
    m_statusLabel->setColor(Color3B::YELLOW);
    this->addChild(m_statusLabel);

    // Username field
    m_usernameField = TextField::create("Username", "fonts/Marker Felt.ttf", 24);
    m_usernameField->setPosition(Vec2(origin.x + visibleSize.width / 2,
                                     origin.y + visibleSize.height / 2 + 100));
    m_usernameField->setMaxLength(50);
    m_usernameField->setMaxLengthEnabled(true);
    this->addChild(m_usernameField);

    // Password field
    m_passwordField = TextField::create("Password", "fonts/Marker Felt.ttf", 24);
    m_passwordField->setPosition(Vec2(origin.x + visibleSize.width / 2,
                                     origin.y + visibleSize.height / 2 + 50));
    m_passwordField->setPasswordEnabled(true);
    m_passwordField->setMaxLength(50);
    m_passwordField->setMaxLengthEnabled(true);
    this->addChild(m_passwordField);

    // Buttons
    auto loginLabel = Label::createWithTTF("Login", "fonts/Marker Felt.ttf", 24);
    m_loginButton = MenuItemLabel::create(loginLabel, CC_CALLBACK_1(AuthSampleScene::onLoginClicked, this));

    auto registerLabel = Label::createWithTTF("Register", "fonts/Marker Felt.ttf", 24);
    m_registerButton = MenuItemLabel::create(registerLabel, CC_CALLBACK_1(AuthSampleScene::onRegisterClicked, this));

    auto logoutLabel = Label::createWithTTF("Logout", "fonts/Marker Felt.ttf", 24);
    m_logoutButton = MenuItemLabel::create(logoutLabel, CC_CALLBACK_1(AuthSampleScene::onLogoutClicked, this));

    auto verifyLabel = Label::createWithTTF("Verify Token", "fonts/Marker Felt.ttf", 24);
    m_verifyButton = MenuItemLabel::create(verifyLabel, CC_CALLBACK_1(AuthSampleScene::onVerifyClicked, this));

    auto menu = Menu::create(m_loginButton, m_registerButton, m_logoutButton, m_verifyButton, nullptr);
    menu->alignItemsVerticallyWithPadding(20);
    menu->setPosition(Vec2(origin.x + visibleSize.width / 2,
                          origin.y + visibleSize.height / 2 - 100));
    this->addChild(menu);
}

void AuthSampleScene::updateUI() {
    if (!m_auth) return;

    bool loggedIn = m_auth->isLoggedIn();
    std::string statusText;

    if (loggedIn) {
        std::string username = m_auth->getCurrentUsername();
        std::string userId = m_auth->getCurrentUserId();
        statusText = "Logged in as: " + username + " (ID: " + userId.substr(0, 8) + "...)";

        m_loginButton->setVisible(false);
        m_registerButton->setVisible(false);
        m_logoutButton->setVisible(true);
        m_verifyButton->setVisible(true);
    } else {
        statusText = "Not logged in";

        m_loginButton->setVisible(true);
        m_registerButton->setVisible(true);
        m_logoutButton->setVisible(false);
        m_verifyButton->setVisible(false);
    }

    m_statusLabel->setString(statusText);
}

void AuthSampleScene::showMessage(const std::string& message) {
    m_statusLabel->setString(message);
    m_statusLabel->setColor(Color3B::GREEN);

    // Reset color after 3 seconds
    this->runAction(Sequence::create(
        DelayTime::create(3.0f),
        CallFunc::create([this]() {
            updateUI();
        }),
        nullptr
    ));
}

void AuthSampleScene::clearFields() {
    m_usernameField->setString("");
    m_passwordField->setString("");
}

void AuthSampleScene::onLoginClicked(Ref* sender) {
    std::string username = m_usernameField->getString();
    std::string password = m_passwordField->getString();

    if (username.empty() || password.empty()) {
        showMessage("Please enter username and password");
        return;
    }

    m_statusLabel->setString("Logging in...");
    m_statusLabel->setColor(Color3B::WHITE);

    m_auth->loginUser(username, password,
        [this](bool success, const std::string& token, const std::string& userId,
               const std::string& username, const std::string& message) {
            if (success) {
                clearFields();
                updateUI();
                showMessage("Login successful! Welcome " + username);
            } else {
                showMessage("Login failed: " + message);
            }
        });
}

void AuthSampleScene::onRegisterClicked(Ref* sender) {
    std::string username = m_usernameField->getString();
    std::string password = m_passwordField->getString();

    if (username.empty() || password.empty()) {
        showMessage("Please enter username and password");
        return;
    }

    if (password.length() < 6) {
        showMessage("Password must be at least 6 characters");
        return;
    }

    m_statusLabel->setString("Registering...");
    m_statusLabel->setColor(Color3B::WHITE);

    m_auth->registerUser(username, password,
        [this](bool success, const std::string& userId, const std::string& message) {
            if (success) {
                clearFields();
                showMessage("Registration successful! You can now login.");
            } else {
                showMessage("Registration failed: " + message);
            }
        });
}

void AuthSampleScene::onLogoutClicked(Ref* sender) {
    m_auth->logoutUser([this](bool success, const std::string& message) {
        updateUI();
        if (success) {
            showMessage("Logged out successfully");
        } else {
            showMessage("Logout failed: " + message);
        }
    });
}

void AuthSampleScene::onVerifyClicked(Ref* sender) {
    // Get the current token (in a real app, this might come from storage)
    auto authHandler = m_auth->getAuthHandler();
    if (!authHandler) {
        showMessage("Auth handler not available");
        return;
    }

    // For demo purposes, we'll create a session and verify it
    m_auth->createSession([this](const std::string& sessionId) {
        if (sessionId.empty()) {
            showMessage("Failed to create session");
            return;
        }

        m_auth->getSessionInfo(sessionId,
            [this, sessionId](bool valid, const std::string& userId, const std::string& username) {
                if (valid) {
                    showMessage("Session valid for user: " + username);
                } else {
                    showMessage("Session invalid");
                }
            });
    });
}