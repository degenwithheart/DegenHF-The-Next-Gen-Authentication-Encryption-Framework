#ifndef __DEGEN_HF_COCOS2DX_SAMPLE_H__
#define __DEGEN_HF_COCOS2DX_SAMPLE_H__

#include "AuthExtension.h"
#include <cocos2d.h>

USING_NS_CC;

/**
 * @brief Sample scene demonstrating DegenHF ECC authentication in Cocos2d-x
 *
 * This scene shows how to integrate authentication into a Cocos2d-x game
 * with login, registration, and session management.
 */
class AuthSampleScene : public Scene {
public:
    static Scene* createScene();

    virtual bool init();

    CREATE_FUNC(AuthSampleScene);

private:
    // UI Elements
    Label* m_statusLabel;
    TextField* m_usernameField;
    TextField* m_passwordField;
    MenuItemLabel* m_loginButton;
    MenuItemLabel* m_registerButton;
    MenuItemLabel* m_logoutButton;
    MenuItemLabel* m_verifyButton;

    // Auth extension
    DegenHF::Cocos2dx::AuthExtension* m_auth;

    // Helper methods
    void setupUI();
    void updateUI();
    void showMessage(const std::string& message);
    void clearFields();

    // Button callbacks
    void onLoginClicked(Ref* sender);
    void onRegisterClicked(Ref* sender);
    void onLogoutClicked(Ref* sender);
    void onVerifyClicked(Ref* sender);
};

#endif // __DEGEN_HF_COCOS2DX_SAMPLE_H__