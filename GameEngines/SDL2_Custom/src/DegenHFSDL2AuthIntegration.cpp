#include "DegenHFSDL2AuthIntegration.hpp"
#include <iostream>
#include <algorithm>

namespace DegenHF {

// TextInput Implementation
TextInput::TextInput(int x, int y, int w, int h, TTF_Font* font, SDL_Color textColor)
    : UIElement(x, y, w, h), cursorPos_(0), focused_(false), font_(font),
      textColor_(textColor), bgColor_{60, 60, 60, 255}, borderColor_{100, 100, 100, 255},
      textTexture_(nullptr), textWidth_(0), textHeight_(0) {
}

void TextInput::render(SDL_Renderer* renderer) {
    // Background
    SDL_SetRenderDrawColor(renderer, bgColor_.r, bgColor_.g, bgColor_.b, bgColor_.a);
    SDL_RenderFillRect(renderer, &rect_);

    // Border
    SDL_SetRenderDrawColor(renderer, borderColor_.r, borderColor_.g, borderColor_.b, borderColor_.a);
    SDL_RenderDrawRect(renderer, &rect_);

    // Highlight border if focused
    if (focused_) {
        SDL_SetRenderDrawColor(renderer, 100, 150, 255, 255);
        SDL_RenderDrawRect(renderer, &rect_);
    }

    // Text
    if (textTexture_) {
        SDL_Rect textRect = {rect_.x + 5, rect_.y + (rect_.h - textHeight_) / 2, textWidth_, textHeight_};
        SDL_RenderCopy(renderer, textTexture_, nullptr, &textRect);
    }

    // Cursor (if focused)
    if (focused_) {
        int cursorX = rect_.x + 5;
        if (textTexture_ && !text_.empty()) {
            // Approximate cursor position (simple implementation)
            cursorX += (textWidth_ * cursorPos_) / text_.size();
        }

        SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
        SDL_RenderDrawLine(renderer, cursorX, rect_.y + 5, cursorX, rect_.y + rect_.h - 5);
    }
}

bool TextInput::handleEvent(const SDL_Event& event) {
    if (event.type == SDL_MOUSEBUTTONDOWN) {
        int mouseX = event.button.x;
        int mouseY = event.button.y;

        bool wasFocused = focused_;
        focused_ = (mouseX >= rect_.x && mouseX <= rect_.x + rect_.w &&
                   mouseY >= rect_.y && mouseY <= rect_.y + rect_.h);

        if (focused_ && !wasFocused) {
            // Move cursor to clicked position (simple implementation)
            cursorPos_ = text_.size();
        }

        return focused_;
    }

    if (!focused_) return false;

    switch (event.type) {
        case SDL_KEYDOWN:
            switch (event.key.keysym.sym) {
                case SDLK_BACKSPACE:
                    if (cursorPos_ > 0) {
                        text_.erase(cursorPos_ - 1, 1);
                        cursorPos_--;
                        updateTexture(nullptr); // Will be updated in render
                    }
                    return true;

                case SDLK_DELETE:
                    if (cursorPos_ < text_.size()) {
                        text_.erase(cursorPos_, 1);
                        updateTexture(nullptr);
                    }
                    return true;

                case SDLK_LEFT:
                    if (cursorPos_ > 0) cursorPos_--;
                    return true;

                case SDLK_RIGHT:
                    if (cursorPos_ < text_.size()) cursorPos_++;
                    return true;

                case SDLK_HOME:
                    cursorPos_ = 0;
                    return true;

                case SDLK_END:
                    cursorPos_ = text_.size();
                    return true;
            }
            break;

        case SDL_TEXTINPUT:
            text_.insert(cursorPos_, event.text.text);
            cursorPos_ += strlen(event.text.text);
            updateTexture(nullptr);
            return true;
    }

    return false;
}

void TextInput::updateTexture(SDL_Renderer* renderer) {
    if (!font_ || !renderer) return;

    if (textTexture_) {
        SDL_DestroyTexture(textTexture_);
        textTexture_ = nullptr;
    }

    if (text_.empty()) {
        textWidth_ = 0;
        textHeight_ = 0;
        return;
    }

    SDL_Surface* surface = TTF_RenderText_Blended(font_, text_.c_str(), textColor_);
    if (surface) {
        textTexture_ = SDL_CreateTextureFromSurface(renderer, surface);
        textWidth_ = surface->w;
        textHeight_ = surface->h;
        SDL_FreeSurface(surface);
    }
}

// Button Implementation
Button::Button(int x, int y, int w, int h, const std::string& text, TTF_Font* font,
               std::function<void()> onClick)
    : UIElement(x, y, w, h), text_(text), font_(font), onClick_(onClick),
      hovered_(false), pressed_(false), textColor_{255, 255, 255, 255},
      bgColor_{70, 70, 70, 255}, hoverColor_{100, 100, 100, 255},
      borderColor_{100, 100, 100, 255}, textTexture_(nullptr),
      textWidth_(0), textHeight_(0), textureDirty_(true) {
}

void Button::render(SDL_Renderer* renderer) {
    if (textureDirty_) {
        updateTexture(renderer);
        textureDirty_ = false;
    }

    // Background
    SDL_Color bg = hovered_ ? hoverColor_ : bgColor_;
    SDL_SetRenderDrawColor(renderer, bg.r, bg.g, bg.b, bg.a);
    SDL_RenderFillRect(renderer, &rect_);

    // Border
    SDL_SetRenderDrawColor(renderer, borderColor_.r, borderColor_.g, borderColor_.b, borderColor_.a);
    SDL_RenderDrawRect(renderer, &rect_);

    // Text
    if (textTexture_) {
        SDL_Rect textRect = {rect_.x + (rect_.w - textWidth_) / 2,
                           rect_.y + (rect_.h - textHeight_) / 2,
                           textWidth_, textHeight_};
        SDL_RenderCopy(renderer, textTexture_, nullptr, &textRect);
    }
}

bool Button::handleEvent(const SDL_Event& event) {
    if (event.type == SDL_MOUSEMOTION) {
        int mouseX = event.motion.x;
        int mouseY = event.motion.y;
        hovered_ = (mouseX >= rect_.x && mouseX <= rect_.x + rect_.w &&
                   mouseY >= rect_.y && mouseY <= rect_.y + rect_.h);
        return hovered_;
    }

    if (event.type == SDL_MOUSEBUTTONDOWN && event.button.button == SDL_BUTTON_LEFT) {
        int mouseX = event.button.x;
        int mouseY = event.button.y;
        if (mouseX >= rect_.x && mouseX <= rect_.x + rect_.w &&
            mouseY >= rect_.y && mouseY <= rect_.y + rect_.h) {
            pressed_ = true;
            return true;
        }
    }

    if (event.type == SDL_MOUSEBUTTONUP && event.button.button == SDL_BUTTON_LEFT) {
        int mouseX = event.button.x;
        int mouseY = event.button.y;
        if (pressed_ && mouseX >= rect_.x && mouseX <= rect_.x + rect_.w &&
            mouseY >= rect_.y && mouseY <= rect_.y + rect_.h) {
            pressed_ = false;
            if (onClick_) {
                onClick_();
            }
            return true;
        }
        pressed_ = false;
    }

    return false;
}

void Button::updateTexture(SDL_Renderer* renderer) {
    if (!font_ || !renderer) return;

    if (textTexture_) {
        SDL_DestroyTexture(textTexture_);
        textTexture_ = nullptr;
    }

    SDL_Surface* surface = TTF_RenderText_Blended(font_, text_.c_str(), textColor_);
    if (surface) {
        textTexture_ = SDL_CreateTextureFromSurface(renderer, surface);
        textWidth_ = surface->w;
        textHeight_ = surface->h;
        SDL_FreeSurface(surface);
    }
}

// Label Implementation
Label::Label(int x, int y, int w, int h, const std::string& text, TTF_Font* font, SDL_Color textColor)
    : UIElement(x, y, w, h), text_(text), font_(font), textColor_(textColor),
      textTexture_(nullptr), textWidth_(0), textHeight_(0), textureDirty_(true) {
}

void Label::render(SDL_Renderer* renderer) {
    if (textureDirty_) {
        updateTexture(renderer);
        textureDirty_ = false;
    }

    if (textTexture_) {
        SDL_Rect textRect = {rect_.x, rect_.y, textWidth_, textHeight_};
        SDL_RenderCopy(renderer, textTexture_, nullptr, &textRect);
    }
}

void Label::updateTexture(SDL_Renderer* renderer) {
    if (!font_ || !renderer) return;

    if (textTexture_) {
        SDL_DestroyTexture(textTexture_);
        textTexture_ = nullptr;
    }

    SDL_Surface* surface = TTF_RenderText_Blended(font_, text_.c_str(), textColor_);
    if (surface) {
        textTexture_ = SDL_CreateTextureFromSurface(renderer, surface);
        textWidth_ = surface->w;
        textHeight_ = surface->h;
        SDL_FreeSurface(surface);
    }
}

// SDL2AuthIntegration Implementation
SDL2AuthIntegration::SDL2AuthIntegration(const Config& config)
    : window_(nullptr), renderer_(nullptr), font_(nullptr),
      config_(config), currentState_(AuthUIState::LOGIN),
      focusedInput_(nullptr) {

    // Initialize auth handler
    authHandler_ = std::make_unique<ECCAuthHandler>(config.authConfig);
}

SDL2AuthIntegration::~SDL2AuthIntegration() {
    shutdown();
}

bool SDL2AuthIntegration::initialize() {
    // Initialize SDL
    if (SDL_Init(SDL_INIT_VIDEO) < 0) {
        std::cerr << "SDL initialization failed: " << SDL_GetError() << std::endl;
        return false;
    }

    // Initialize SDL_ttf
    if (TTF_Init() < 0) {
        std::cerr << "SDL_ttf initialization failed: " << TTF_GetError() << std::endl;
        SDL_Quit();
        return false;
    }

    // Create window
    window_ = SDL_CreateWindow(config_.windowTitle.c_str(),
                              SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                              config_.windowWidth, config_.windowHeight,
                              SDL_WINDOW_SHOWN);
    if (!window_) {
        std::cerr << "Window creation failed: " << SDL_GetError() << std::endl;
        shutdown();
        return false;
    }

    // Create renderer
    renderer_ = SDL_CreateRenderer(window_, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer_) {
        std::cerr << "Renderer creation failed: " << SDL_GetError() << std::endl;
        shutdown();
        return false;
    }

    // Load font
    font_ = TTF_OpenFont(config_.fontPath.c_str(), config_.fontSize);
    if (!font_) {
        std::cerr << "Font loading failed: " << TTF_GetError() << std::endl;
        // Try to create a fallback font or continue without font
        std::cerr << "Warning: Continuing without font - UI will not display text" << std::endl;
    }

    // Initialize authentication handler
    if (!authHandler_->initialize()) {
        std::cerr << "Authentication handler initialization failed" << std::endl;
        shutdown();
        return false;
    }

    // Create initial UI
    createLoginUI();

    return true;
}

void SDL2AuthIntegration::shutdown() {
    clearUI();

    if (font_) {
        TTF_CloseFont(font_);
        font_ = nullptr;
    }

    if (renderer_) {
        SDL_DestroyRenderer(renderer_);
        renderer_ = nullptr;
    }

    if (window_) {
        SDL_DestroyWindow(window_);
        window_ = nullptr;
    }

    TTF_Quit();
    SDL_Quit();

    authHandler_.reset();
}

bool SDL2AuthIntegration::run() {
    bool running = true;
    SDL_Event event;

    while (running) {
        // Handle events
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT) {
                running = false;
                if (onQuit_) onQuit_();
                break;
            }

            handleEvents();
        }

        if (!running) break;

        // Render
        render();

        // Small delay to prevent excessive CPU usage
        SDL_Delay(16); // ~60 FPS
    }

    return !running; // Return true if user quit
}

void SDL2AuthIntegration::showLoginScreen() {
    currentState_ = AuthUIState::LOGIN;
    clearUI();
    createLoginUI();
}

void SDL2AuthIntegration::showRegisterScreen() {
    currentState_ = AuthUIState::REGISTER;
    clearUI();
    createRegisterUI();
}

void SDL2AuthIntegration::showLoggedInScreen() {
    currentState_ = AuthUIState::LOGGED_IN;
    clearUI();
    createLoggedInUI();
}

void SDL2AuthIntegration::showError(const std::string& message) {
    currentState_ = AuthUIState::ERROR;
    errorMessage_ = message;
    // Keep existing UI but update status
    setStatusMessage(message, config_.errorColor);
}

void SDL2AuthIntegration::createLoginUI() {
    int centerX = config_.windowWidth / 2;
    int startY = 150;
    int elementWidth = 300;

    // Title
    auto titleLabel = std::make_unique<Label>(0, startY, elementWidth, 50, "Login to DegenHF", font_);
    centerUIElement(titleLabel.get(), startY);
    uiElements_.push_back(std::move(titleLabel));

    // Username input
    auto usernameInput = std::make_unique<TextInput>(0, startY + 80, elementWidth, INPUT_HEIGHT, font_);
    centerUIElement(usernameInput.get(), startY + 80);
    uiElements_.push_back(std::move(usernameInput));

    // Password input
    auto passwordInput = std::make_unique<TextInput>(0, startY + 140, elementWidth, INPUT_HEIGHT, font_);
    centerUIElement(passwordInput.get(), startY + 140);
    uiElements_.push_back(std::move(passwordInput));

    // Login button
    auto loginButton = std::make_unique<Button>(0, startY + 200, elementWidth, BUTTON_HEIGHT,
                                               "Login", font_,
                                               [this, usernameInputPtr = usernameInput.get(),
                                                passwordInputPtr = passwordInput.get()]() {
        std::string username = usernameInputPtr->getText();
        std::string password = passwordInputPtr->getText();
        performLogin(username, password);
    });
    centerUIElement(loginButton.get(), startY + 200);
    uiElements_.push_back(std::move(loginButton));

    // Register button
    auto registerButton = std::make_unique<Button>(0, startY + 270, elementWidth, BUTTON_HEIGHT,
                                                  "Create Account", font_,
                                                  [this]() { showRegisterScreen(); });
    centerUIElement(registerButton.get(), startY + 270);
    uiElements_.push_back(std::move(registerButton));

    // Status label
    auto statusLabel = std::make_unique<Label>(0, startY + 340, elementWidth, LABEL_HEIGHT,
                                              "", font_);
    centerUIElement(statusLabel.get(), startY + 340);
    uiElements_.push_back(std::move(statusLabel));
}

void SDL2AuthIntegration::createRegisterUI() {
    int centerX = config_.windowWidth / 2;
    int startY = 120;
    int elementWidth = 300;

    // Title
    auto titleLabel = std::make_unique<Label>(0, startY, elementWidth, 50, "Create Account", font_);
    centerUIElement(titleLabel.get(), startY);
    uiElements_.push_back(std::move(titleLabel));

    // Username input
    auto usernameInput = std::make_unique<TextInput>(0, startY + 80, elementWidth, INPUT_HEIGHT, font_);
    centerUIElement(usernameInput.get(), startY + 80);
    uiElements_.push_back(std::move(usernameInput));

    // Password input
    auto passwordInput = std::make_unique<TextInput>(0, startY + 140, elementWidth, INPUT_HEIGHT, font_);
    centerUIElement(passwordInput.get(), startY + 140);
    uiElements_.push_back(std::move(passwordInput));

    // Confirm password input
    auto confirmInput = std::make_unique<TextInput>(0, startY + 200, elementWidth, INPUT_HEIGHT, font_);
    centerUIElement(confirmInput.get(), startY + 200);
    uiElements_.push_back(std::move(confirmInput));

    // Register button
    auto registerButton = std::make_unique<Button>(0, startY + 270, elementWidth, BUTTON_HEIGHT,
                                                  "Register", font_,
                                                  [this, usernameInputPtr = usernameInput.get(),
                                                   passwordInputPtr = passwordInput.get(),
                                                   confirmInputPtr = confirmInput.get()]() {
        std::string username = usernameInputPtr->getText();
        std::string password = passwordInputPtr->getText();
        std::string confirm = confirmInputPtr->getText();

        if (password != confirm) {
            showError("Passwords do not match");
            return;
        }

        performRegister(username, password);
    });
    centerUIElement(registerButton.get(), startY + 270);
    uiElements_.push_back(std::move(registerButton));

    // Back to login button
    auto backButton = std::make_unique<Button>(0, startY + 340, elementWidth, BUTTON_HEIGHT,
                                              "Back to Login", font_,
                                              [this]() { showLoginScreen(); });
    centerUIElement(backButton.get(), startY + 340);
    uiElements_.push_back(std::move(backButton));

    // Status label
    auto statusLabel = std::make_unique<Label>(0, startY + 410, elementWidth, LABEL_HEIGHT,
                                              "", font_);
    centerUIElement(statusLabel.get(), startY + 410);
    uiElements_.push_back(std::move(statusLabel));
}

void SDL2AuthIntegration::createLoggedInUI() {
    int centerX = config_.windowWidth / 2;
    int startY = 200;
    int elementWidth = 300;

    // Welcome message
    std::string welcomeText = "Welcome, " + getCurrentUsername() + "!";
    auto welcomeLabel = std::make_unique<Label>(0, startY, elementWidth, 50, welcomeText, font_,
                                               config_.successColor);
    centerUIElement(welcomeLabel.get(), startY);
    uiElements_.push_back(std::move(welcomeLabel));

    // User info
    std::string infoText = "User ID: " + getCurrentUserId();
    auto infoLabel = std::make_unique<Label>(0, startY + 70, elementWidth, 30, infoText, font_);
    centerUIElement(infoLabel.get(), startY + 70);
    uiElements_.push_back(std::move(infoLabel));

    // Logout button
    auto logoutButton = std::make_unique<Button>(0, startY + 130, elementWidth, BUTTON_HEIGHT,
                                                "Logout", font_,
                                                [this]() { performLogout(); });
    centerUIElement(logoutButton.get(), startY + 130);
    uiElements_.push_back(std::move(logoutButton));

    // Status label
    auto statusLabel = std::make_unique<Label>(0, startY + 200, elementWidth, LABEL_HEIGHT,
                                              "Successfully authenticated!", font_,
                                              config_.successColor);
    centerUIElement(statusLabel.get(), startY + 200);
    uiElements_.push_back(std::move(statusLabel));
}

void SDL2AuthIntegration::clearUI() {
    uiElements_.clear();
    focusedInput_ = nullptr;
}

void SDL2AuthIntegration::handleEvents() {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        // Global event handling
        switch (event.type) {
            case SDL_QUIT:
                if (onQuit_) onQuit_();
                return;

            case SDL_KEYDOWN:
                handleKeyDown(event.key);
                break;

            case SDL_TEXTINPUT:
                handleTextInput(event.text);
                break;

            case SDL_MOUSEBUTTONDOWN:
            case SDL_MOUSEBUTTONUP:
                handleMouseButton(event.button);
                break;
        }

        // UI element event handling
        for (auto& element : uiElements_) {
            if (element->handleEvent(event)) {
                break; // Event was handled
            }
        }
    }
}

void SDL2AuthIntegration::handleKeyDown(const SDL_KeyboardEvent& keyEvent) {
    // Handle focused input
    if (focusedInput_) {
        SDL_Event syntheticEvent;
        syntheticEvent.type = SDL_KEYDOWN;
        syntheticEvent.key = keyEvent;
        focusedInput_->handleEvent(syntheticEvent);
    }

    // Global shortcuts
    if (keyEvent.keysym.sym == SDLK_ESCAPE) {
        if (currentState_ == AuthUIState::REGISTER) {
            showLoginScreen();
        }
    }
}

void SDL2AuthIntegration::handleTextInput(const SDL_TextInputEvent& textEvent) {
    if (focusedInput_) {
        SDL_Event syntheticEvent;
        syntheticEvent.type = SDL_TEXTINPUT;
        syntheticEvent.text = textEvent;
        focusedInput_->handleEvent(syntheticEvent);
    }
}

void SDL2AuthIntegration::handleMouseButton(const SDL_MouseButtonEvent& buttonEvent) {
    // Update focused input
    focusedInput_ = nullptr;
    for (auto& element : uiElements_) {
        if (auto input = dynamic_cast<TextInput*>(element.get())) {
            SDL_Event syntheticEvent;
            syntheticEvent.type = SDL_MOUSEBUTTONDOWN;
            syntheticEvent.button = buttonEvent;
            if (input->handleEvent(syntheticEvent)) {
                focusedInput_ = input;
                break;
            }
        }
    }
}

void SDL2AuthIntegration::render() {
    // Clear screen
    renderBackground();

    // Render UI elements
    for (auto& element : uiElements_) {
        element->render(renderer_);
    }

    // Present
    SDL_RenderPresent(renderer_);
}

void SDL2AuthIntegration::renderBackground() {
    SDL_SetRenderDrawColor(renderer_, config_.bgColor.r, config_.bgColor.g,
                          config_.bgColor.b, config_.bgColor.a);
    SDL_RenderClear(renderer_);
}

void SDL2AuthIntegration::performLogin(const std::string& username, const std::string& password) {
    if (username.empty() || password.empty()) {
        showError("Please enter username and password");
        return;
    }

    setStatusMessage("Logging in...", config_.accentColor);

    // Perform authentication (in a real implementation, this might be async)
    AuthResult result = authHandler_->authenticateUser(username, password);

    if (result.success) {
        setStatusMessage("Login successful!", config_.successColor);
        showLoggedInScreen();
        if (onLoginSuccess_) {
            onLoginSuccess_(username);
        }
    } else {
        showError("Login failed: " + result.errorMessage);
    }
}

void SDL2AuthIntegration::performRegister(const std::string& username, const std::string& password) {
    if (username.empty() || password.empty()) {
        showError("Please enter username and password");
        return;
    }

    if (username.length() < 3) {
        showError("Username must be at least 3 characters");
        return;
    }

    if (password.length() < 6) {
        showError("Password must be at least 6 characters");
        return;
    }

    setStatusMessage("Creating account...", config_.accentColor);

    // Perform registration
    AuthResult result = authHandler_->registerUser(username, password);

    if (result.success) {
        setStatusMessage("Account created successfully!", config_.successColor);
        // Auto-login after successful registration
        performLogin(username, password);
        if (onRegisterSuccess_) {
            onRegisterSuccess_(username);
        }
    } else {
        showError("Registration failed: " + result.errorMessage);
    }
}

void SDL2AuthIntegration::performLogout() {
    authHandler_->logout();
    setStatusMessage("Logged out successfully", config_.accentColor);
    showLoginScreen();
    if (onLogout_) {
        onLogout_();
    }
}

void SDL2AuthIntegration::setStatusMessage(const std::string& message, SDL_Color color) {
    statusMessage_ = message;

    // Find status label and update it
    for (auto& element : uiElements_) {
        if (auto label = dynamic_cast<Label*>(element.get())) {
            // This is a simple heuristic - in a real implementation,
            // you'd want to tag UI elements properly
            if (label->getRect().y > config_.windowHeight / 2) {
                label->setText(message);
                label->setColor(color);
                break;
            }
        }
    }
}

void SDL2AuthIntegration::centerUIElement(UIElement* element, int yOffset) {
    if (!element) return;

    SDL_Rect rect = element->getRect();
    int centerX = (config_.windowWidth - rect.w) / 2;
    element->setPosition(centerX, yOffset > 0 ? yOffset : rect.y);
}

SDL_Texture* SDL2AuthIntegration::createTextTexture(const std::string& text, SDL_Color color) {
    if (!font_ || !renderer_) return nullptr;

    SDL_Surface* surface = TTF_RenderText_Blended(font_, text.c_str(), color);
    if (!surface) return nullptr;

    SDL_Texture* texture = SDL_CreateTextureFromSurface(renderer_, surface);
    SDL_FreeSurface(surface);

    return texture;
}

} // namespace DegenHF