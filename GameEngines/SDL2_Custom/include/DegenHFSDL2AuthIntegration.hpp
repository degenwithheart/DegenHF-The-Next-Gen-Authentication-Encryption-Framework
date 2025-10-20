#ifndef DEGENHF_SDL2_AUTH_INTEGRATION_HPP
#define DEGENHF_SDL2_AUTH_INTEGRATION_HPP

#include "DegenHFECCAuthHandler.hpp"
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <string>
#include <memory>
#include <functional>
#include <vector>

namespace DegenHF {

// Forward declarations
class SDL2AuthIntegration;

// UI Element base class
class UIElement {
public:
    UIElement(int x, int y, int w, int h) : rect_{x, y, w, h} {}
    virtual ~UIElement() = default;

    virtual void render(SDL_Renderer* renderer) = 0;
    virtual bool handleEvent(const SDL_Event& event) = 0;

    SDL_Rect getRect() const { return rect_; }
    void setPosition(int x, int y) { rect_.x = x; rect_.y = y; }

protected:
    SDL_Rect rect_;
};

// Text Input Field
class TextInput : public UIElement {
public:
    TextInput(int x, int y, int w, int h, TTF_Font* font, SDL_Color textColor = {255, 255, 255, 255});

    void render(SDL_Renderer* renderer) override;
    bool handleEvent(const SDL_Event& event) override;

    std::string getText() const { return text_; }
    void setText(const std::string& text) { text_ = text; cursorPos_ = text.size(); }
    void clear() { text_.clear(); cursorPos_ = 0; }
    bool isFocused() const { return focused_; }
    void setFocused(bool focused) { focused_ = focused; }

private:
    std::string text_;
    size_t cursorPos_;
    bool focused_;
    TTF_Font* font_;
    SDL_Color textColor_;
    SDL_Color bgColor_;
    SDL_Color borderColor_;
    SDL_Texture* textTexture_;
    int textWidth_;
    int textHeight_;

    void updateTexture(SDL_Renderer* renderer);
};

// Button
class Button : public UIElement {
public:
    Button(int x, int y, int w, int h, const std::string& text, TTF_Font* font,
           std::function<void()> onClick = nullptr);

    void render(SDL_Renderer* renderer) override;
    bool handleEvent(const SDL_Event& event) override;

    void setText(const std::string& text) { text_ = text; textureDirty_ = true; }
    void setOnClick(std::function<void()> callback) { onClick_ = callback; }
    bool isHovered() const { return hovered_; }

private:
    std::string text_;
    TTF_Font* font_;
    std::function<void()> onClick_;
    bool hovered_;
    bool pressed_;
    SDL_Color textColor_;
    SDL_Color bgColor_;
    SDL_Color hoverColor_;
    SDL_Color borderColor_;
    SDL_Texture* textTexture_;
    int textWidth_;
    int textHeight_;
    bool textureDirty_;

    void updateTexture(SDL_Renderer* renderer);
};

// Label
class Label : public UIElement {
public:
    Label(int x, int y, int w, int h, const std::string& text, TTF_Font* font,
          SDL_Color textColor = {255, 255, 255, 255});

    void render(SDL_Renderer* renderer) override;
    bool handleEvent(const SDL_Event& event) override { return false; }

    void setText(const std::string& text) { text_ = text; textureDirty_ = true; }
    void setColor(SDL_Color color) { textColor_ = color; textureDirty_ = true; }

private:
    std::string text_;
    TTF_Font* font_;
    SDL_Color textColor_;
    SDL_Texture* textTexture_;
    int textWidth_;
    int textHeight_;
    bool textureDirty_;

    void updateTexture(SDL_Renderer* renderer);
};

// Authentication UI States
enum class AuthUIState {
    LOGIN,
    REGISTER,
    LOGGED_IN,
    ERROR
};

// Main SDL2 Authentication Integration Class
class SDL2AuthIntegration {
public:
    // Configuration
    struct Config {
        int windowWidth = 800;
        int windowHeight = 600;
        std::string windowTitle = "DegenHF Authentication";
        std::string fontPath = "assets/fonts/default.ttf";
        int fontSize = 24;
        AuthConfig authConfig;
        SDL_Color bgColor = {40, 40, 40, 255};
        SDL_Color uiColor = {60, 60, 60, 255};
        SDL_Color accentColor = {100, 150, 255, 255};
        SDL_Color errorColor = {255, 100, 100, 255};
        SDL_Color successColor = {100, 255, 100, 255};
    };

    // Constructor and Destructor
    explicit SDL2AuthIntegration(const Config& config = Config());
    ~SDL2AuthIntegration();

    // Initialization and Main Loop
    bool initialize();
    void shutdown();
    bool run(); // Main event loop - returns false when user wants to quit

    // Authentication State
    bool isAuthenticated() const { return authHandler_ && authHandler_->isUserLoggedIn(); }
    std::string getCurrentUsername() const {
        return authHandler_ ? authHandler_->getCurrentUsername() : "";
    }
    std::string getCurrentUserId() const {
        return authHandler_ ? authHandler_->getCurrentUserId() : "";
    }

    // UI State Management
    void showLoginScreen();
    void showRegisterScreen();
    void showLoggedInScreen();
    void showError(const std::string& message);

    // Event Callbacks
    void setOnLoginSuccess(std::function<void(const std::string& username)> callback) {
        onLoginSuccess_ = callback;
    }
    void setOnRegisterSuccess(std::function<void(const std::string& username)> callback) {
        onRegisterSuccess_ = callback;
    }
    void setOnLogout(std::function<void()> callback) {
        onLogout_ = callback;
    }
    void setOnQuit(std::function<void()> callback) {
        onQuit_ = callback;
    }

    // SDL Access (for game integration)
    SDL_Window* getWindow() const { return window_; }
    SDL_Renderer* getRenderer() const { return renderer_; }

private:
    // SDL Components
    SDL_Window* window_;
    SDL_Renderer* renderer_;
    TTF_Font* font_;

    // Authentication
    std::unique_ptr<ECCAuthHandler> authHandler_;

    // Configuration
    Config config_;

    // UI State
    AuthUIState currentState_;
    std::string errorMessage_;
    std::string statusMessage_;

    // UI Elements
    std::vector<std::unique_ptr<UIElement>> uiElements_;

    // Current focused input
    TextInput* focusedInput_;

    // Event Callbacks
    std::function<void(const std::string&)> onLoginSuccess_;
    std::function<void(const std::string&)> onRegisterSuccess_;
    std::function<void()> onLogout_;
    std::function<void()> onQuit_;

    // UI Creation Methods
    void createLoginUI();
    void createRegisterUI();
    void createLoggedInUI();
    void clearUI();

    // Event Handling
    void handleEvents();
    void handleKeyDown(const SDL_KeyboardEvent& keyEvent);
    void handleTextInput(const SDL_TextInputEvent& textEvent);
    void handleMouseButton(const SDL_MouseButtonEvent& buttonEvent);

    // Rendering
    void render();
    void renderBackground();

    // Authentication Actions
    void performLogin(const std::string& username, const std::string& password);
    void performRegister(const std::string& username, const std::string& password);
    void performLogout();

    // Utility
    void setStatusMessage(const std::string& message, SDL_Color color = {255, 255, 255, 255});
    void centerUIElement(UIElement* element, int yOffset = 0);
    SDL_Texture* createTextTexture(const std::string& text, SDL_Color color);

    // Constants
    static constexpr int UI_PADDING = 20;
    static constexpr int INPUT_HEIGHT = 40;
    static constexpr int BUTTON_HEIGHT = 50;
    static constexpr int LABEL_HEIGHT = 30;
};

} // namespace DegenHF

#endif // DEGENHF_SDL2_AUTH_INTEGRATION_HPP