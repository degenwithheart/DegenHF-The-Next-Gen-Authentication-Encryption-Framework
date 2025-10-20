#include "DegenHFSDL2AuthIntegration.hpp"
#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    std::cout << "DegenHF SDL2 Authentication Example" << std::endl;
    std::cout << "==================================" << std::endl;

    // Configure the authentication integration
    DegenHF::SDL2AuthIntegration::Config config;
    config.windowTitle = "DegenHF Game Authentication";
    config.windowWidth = 800;
    config.windowHeight = 600;
    config.fontPath = "assets/fonts/arial.ttf"; // You'll need to provide a font file
    config.fontSize = 24;

    // Configure authentication settings
    config.authConfig.hashIterations = 10000;
    config.authConfig.tokenExpiryHours = 24;
    config.authConfig.userDataPath = "game_auth_data";

    // Create and initialize the authentication integration
    auto authIntegration = std::make_unique<DegenHF::SDL2AuthIntegration>(config);

    if (!authIntegration->initialize()) {
        std::cerr << "Failed to initialize SDL2 authentication integration" << std::endl;
        return 1;
    }

    // Set up event callbacks
    authIntegration->setOnLoginSuccess([](const std::string& username) {
        std::cout << "Login successful for user: " << username << std::endl;
        std::cout << "Starting game..." << std::endl;
        // Here you would transition to your main game loop
    });

    authIntegration->setOnRegisterSuccess([](const std::string& username) {
        std::cout << "Registration successful for user: " << username << std::endl;
    });

    authIntegration->setOnLogout([]() {
        std::cout << "User logged out" << std::endl;
    });

    authIntegration->setOnQuit([]() {
        std::cout << "Application quit by user" << std::endl;
    });

    std::cout << "Authentication UI initialized. Use the window to login or register." << std::endl;
    std::cout << "Press ESC in register screen to go back to login." << std::endl;
    std::cout << "Close the window to quit." << std::endl;
    std::cout << std::endl;

    // Run the authentication UI main loop
    // This will block until the user closes the window or authentication is complete
    bool shouldQuit = authIntegration->run();

    if (shouldQuit) {
        std::cout << "Authentication complete. Cleaning up..." << std::endl;
    }

    // The authIntegration will be automatically cleaned up when it goes out of scope
    return 0;
}

// Example of how you might integrate this into a larger SDL2 game
class MyGame {
public:
    MyGame() : authenticated_(false) {}

    bool initialize() {
        // Initialize SDL and your game...

        // Set up authentication
        DegenHF::SDL2AuthIntegration::Config authConfig;
        authConfig.windowTitle = "My Awesome Game - Login";
        authConfig.authConfig.userDataPath = "MyGame/SaveData/Auth";

        authIntegration_ = std::make_unique<DegenHF::SDL2AuthIntegration>(authConfig);

        if (!authIntegration_->initialize()) {
            return false;
        }

        // Set up callbacks
        authIntegration_->setOnLoginSuccess([this](const std::string& username) {
            this->authenticated_ = true;
            this->currentUsername_ = username;
            std::cout << "Welcome to the game, " << username << "!" << std::endl;
        });

        authIntegration_->setOnLogout([this]() {
            this->authenticated_ = false;
            this->currentUsername_.clear();
            std::cout << "Logged out of game" << std::endl;
        });

        return true;
    }

    void run() {
        bool running = true;
        SDL_Event event;

        while (running) {
            // If not authenticated, show auth screen
            if (!authenticated_) {
                if (authIntegration_->run()) {
                    // User quit from auth screen
                    running = false;
                }
                continue;
            }

            // Main game loop when authenticated
            while (SDL_PollEvent(&event)) {
                if (event.type == SDL_QUIT) {
                    running = false;
                    break;
                }

                // Handle your game events here
                handleGameEvent(event);
            }

            if (!running) break;

            // Update game logic
            updateGame();

            // Render game
            renderGame();

            SDL_Delay(16); // ~60 FPS
        }
    }

    void handleGameEvent(const SDL_Event& event) {
        // Your game event handling logic
        switch (event.type) {
            case SDL_KEYDOWN:
                if (event.key.keysym.sym == SDLK_ESCAPE) {
                    // Show in-game menu or logout
                    showGameMenu();
                }
                break;
            // Handle other game events...
        }
    }

    void updateGame() {
        // Your game update logic
        // Could include saving game progress using authenticated user ID
        if (authenticated_) {
            std::string userId = authIntegration_->getCurrentUserId();
            // Save game progress for this user
            saveGameProgress(userId);
        }
    }

    void renderGame() {
        // Clear screen
        SDL_SetRenderDrawColor(gameRenderer_, 0, 0, 0, 255);
        SDL_RenderClear(gameRenderer_);

        // Render your game here
        // ...

        // Show authenticated user info
        if (authenticated_) {
            renderUI();
        }

        SDL_RenderPresent(gameRenderer_);
    }

    void renderUI() {
        // Render user info, logout button, etc.
        // You could use the same UI system as the auth integration
    }

    void showGameMenu() {
        // Show in-game menu with logout option
        // Could create a simple menu using SDL2
    }

    void saveGameProgress(const std::string& userId) {
        // Save game data associated with the authenticated user
        // This ensures save files are properly segregated by user
    }

    void shutdown() {
        authIntegration_.reset();
        // Clean up your game resources...
    }

private:
    std::unique_ptr<DegenHF::SDL2AuthIntegration> authIntegration_;
    SDL_Window* gameWindow_;
    SDL_Renderer* gameRenderer_;
    bool authenticated_;
    std::string currentUsername_;
};

// Alternative: Using the ECC Auth Handler directly (without SDL2 UI)
void exampleDirectUsage() {
    std::cout << "Direct ECC Auth Handler Example" << std::endl;

    // Create auth handler
    DegenHF::AuthConfig config;
    config.hashIterations = 10000;
    config.userDataPath = "direct_auth_example";

    DegenHF::ECCAuthHandler authHandler(config);

    if (!authHandler.initialize()) {
        std::cerr << "Failed to initialize auth handler" << std::endl;
        return;
    }

    // Register a user
    std::cout << "Registering user..." << std::endl;
    DegenHF::AuthResult regResult = authHandler.registerUser("example_user", "secure_password123");

    if (regResult.success) {
        std::cout << "Registration successful! User ID: " << regResult.userId << std::endl;

        // Login
        std::cout << "Logging in..." << std::endl;
        DegenHF::AuthResult loginResult = authHandler.authenticateUser("example_user", "secure_password123");

        if (loginResult.success) {
            std::cout << "Login successful!" << std::endl;
            std::cout << "Token: " << loginResult.token << std::endl;
            std::cout << "Session ID: " << loginResult.sessionId << std::endl;

            // Verify token
            auto tokenOpt = authHandler.verifyToken(loginResult.token);
            if (tokenOpt) {
                std::cout << "Token verification successful!" << std::endl;
                std::cout << "Token user: " << tokenOpt->username << std::endl;
            }

            // Logout
            authHandler.logout();
            std::cout << "Logged out" << std::endl;
        } else {
            std::cout << "Login failed: " << loginResult.errorMessage << std::endl;
        }
    } else {
        std::cout << "Registration failed: " << regResult.errorMessage << std::endl;
    }
}

int main_direct(int argc, char* argv[]) {
    exampleDirectUsage();
    return 0;
}