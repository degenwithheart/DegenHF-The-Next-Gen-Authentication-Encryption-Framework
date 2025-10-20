# DegenHF SDL2 + Custom Game Engine Integration

This directory contains the SDL2 integration for DegenHF's ECC-based authentication system, providing blockchain-grade security for SDL2-based games and custom game engines.

## Features

- **ECC Cryptography**: C++ implementation of secp256k1 elliptic curve cryptography
- **SDL2 UI Integration**: Complete authentication UI with login/register screens
- **Hybrid Password Hashing**: PBKDF2 with SHA-256 for secure password storage
- **JWT-like Token System**: Secure authentication tokens with expiration
- **Session Management**: Persistent sessions across game restarts
- **Cross-Platform**: Works on all SDL2 supported platforms
- **Thread-Safe**: Concurrent access protection with mutexes
- **Data Persistence**: JSON-based secure local storage
- **Event-Driven Architecture**: Callback-based event handling

## Directory Structure

```
SDL2_Custom/
├── include/
│   ├── DegenHFECCAuthHandler.hpp     # Core ECC authentication logic
│   └── DegenHFSDL2AuthIntegration.hpp # SDL2 UI integration
├── src/
│   ├── DegenHFECCAuthHandler.cpp     # Core implementation
│   └── DegenHFSDL2AuthIntegration.cpp # SDL2 UI implementation
├── examples/
│   └── main.cpp                      # Usage examples
├── tests/
│   └── test_auth.cpp                 # Comprehensive test suite
├── cmake/
│   └── DegenHFSDL2AuthConfig.cmake.in # CMake config template
├── CMakeLists.txt                    # Build configuration
├── README.md                         # This documentation
└── LICENSE                           # License information
```

## Requirements

### Dependencies
- **C++17** or later
- **SDL2** (2.0.0 or later)
- **SDL2_ttf** for text rendering
- **OpenSSL** (1.1.0 or later) for cryptography
- **nlohmann/json** (3.0.0 or later) for data persistence
- **CMake** (3.16 or later) for building

### Platform Support
- **Linux**: Full support
- **Windows**: Full support (MSVC or MinGW)
- **macOS**: Full support
- **FreeBSD**: Full support
- **Other Unix-like**: Should work with SDL2 support

## Installation

### Method 1: CMake Build (Recommended)

```bash
# Clone or navigate to the SDL2_Custom directory
cd GameEngines/SDL2_Custom

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build the library
make -j$(nproc)

# Install (optional)
sudo make install
```

### Method 2: Manual Build

Ensure all dependencies are installed:

```bash
# Ubuntu/Debian
sudo apt-get install libsdl2-dev libsdl2-ttf-dev libssl-dev nlohmann-json3-dev cmake build-essential

# macOS (with Homebrew)
brew install sdl2 sdl2_ttf openssl nlohmann-json cmake

# CentOS/RHEL/Fedora
sudo dnf install SDL2-devel SDL2_ttf-devel openssl-devel json-devel cmake gcc-c++
```

Then build as above.

### Method 3: Integration into Existing Project

Add the source files to your project:

```cmake
# In your CMakeLists.txt
add_subdirectory(path/to/SDL2_Custom)

# Link the library
target_link_libraries(your_game degenhf_sdl2_auth)
```

## Setup

### Basic Initialization

```cpp
#include "DegenHFECCAuthHandler.hpp"

// Configure authentication
DegenHF::AuthConfig config;
config.hashIterations = 10000;
config.tokenExpiryHours = 24;
config.userDataPath = "MyGame/AuthData";

// Create and initialize auth handler
DegenHF::ECCAuthHandler authHandler(config);
if (!authHandler.initialize()) {
    std::cerr << "Failed to initialize authentication" << std::endl;
    return 1;
}
```

### SDL2 UI Integration

```cpp
#include "DegenHFSDL2AuthIntegration.hpp"

// Configure UI
DegenHF::SDL2AuthIntegration::Config uiConfig;
uiConfig.windowTitle = "My Game - Authentication";
uiConfig.windowWidth = 800;
uiConfig.windowHeight = 600;
uiConfig.fontPath = "assets/fonts/arial.ttf";

// Create UI integration
auto authUI = std::make_unique<DegenHF::SDL2AuthIntegration>(uiConfig);
if (!authUI->initialize()) {
    std::cerr << "Failed to initialize auth UI" << std::endl;
    return 1;
}

// Set callbacks
authUI->setOnLoginSuccess([](const std::string& username) {
    std::cout << "Welcome, " << username << "!" << std::endl;
    // Transition to game
});

authUI->setOnQuit([]() {
    // Handle quit
});

// Run authentication UI
authUI->run();
```

## Basic Usage

### User Registration

```cpp
// Register a new user
DegenHF::AuthResult result = authHandler.registerUser("player1", "secure_password123");

if (result.success) {
    std::cout << "Registration successful! User ID: " << result.userId << std::endl;
} else {
    std::cout << "Registration failed: " << result.errorMessage << std::endl;
}
```

### User Authentication

```cpp
// Authenticate user
DegenHF::AuthResult result = authHandler.authenticateUser("player1", "secure_password123");

if (result.success) {
    std::cout << "Login successful!" << std::endl;
    std::cout << "Token: " << result.token << std::endl;
    std::cout << "Session ID: " << result.sessionId << std::endl;

    // Store token for session management
    std::string authToken = result.token;
} else {
    std::cout << "Login failed: " << result.errorMessage << std::endl;
}
```

### Token Verification

```cpp
// Verify stored token
auto tokenOpt = authHandler.verifyToken(authToken);

if (tokenOpt) {
    std::cout << "Token valid for user: " << tokenOpt->username << std::endl;
} else {
    std::cout << "Token invalid or expired" << std::endl;
}
```

### Session Management

```cpp
// Get current session
auto sessionOpt = authHandler.getSession(sessionId);

if (sessionOpt && sessionOpt->isActive) {
    std::cout << "Session active for: " << sessionOpt->username << std::endl;
} else {
    std::cout << "Session invalid" << std::endl;
}
```

### Logout

```cpp
// Logout user
authHandler.logout();
std::cout << "User logged out" << std::endl;
```

## Advanced Usage

### Custom UI Integration

```cpp
class CustomAuthUI {
public:
    CustomAuthUI(DegenHF::ECCAuthHandler& auth) : auth_(auth) {}

    void showLoginScreen() {
        // Your custom UI implementation
        std::string username, password;
        // Get input from your UI system...

        auto result = auth_.authenticateUser(username, password);
        if (result.success) {
            onLoginSuccess(result.username);
        } else {
            showError(result.errorMessage);
        }
    }

    void showRegisterScreen() {
        // Your custom registration UI...
    }

private:
    DegenHF::ECCAuthHandler& auth_;
    std::function<void(const std::string&)> onLoginSuccess;
    std::function<void(const std::string&)> onRegisterSuccess;
};
```

### Game Integration Example

```cpp
class GameWithAuth {
public:
    bool initialize() {
        // Initialize SDL2...

        // Set up authentication
        DegenHF::AuthConfig authConfig;
        authConfig.userDataPath = "MyGame/SaveData/Auth";

        authHandler_ = std::make_unique<DegenHF::ECCAuthHandler>(authConfig);
        if (!authHandler_->initialize()) {
            return false;
        }

        // Try to load existing session
        if (!tryAutoLogin()) {
            showAuthScreen();
        }

        return true;
    }

    void run() {
        bool running = true;
        SDL_Event event;

        while (running) {
            while (SDL_PollEvent(&event)) {
                if (event.type == SDL_QUIT) {
                    running = false;
                }

                if (!authenticated_) {
                    handleAuthEvent(event);
                } else {
                    handleGameEvent(event);
                }
            }

            if (authenticated_) {
                updateGame();
                renderGame();
            } else {
                renderAuthScreen();
            }

            SDL_Delay(16);
        }
    }

private:
    bool tryAutoLogin() {
        // Try to load saved auth state
        authHandler_->loadAuthData();

        if (authHandler_->isUserLoggedIn()) {
            authenticated_ = true;
            currentUsername_ = authHandler_->getCurrentUsername();
            loadUserGameData(currentUsername_);
            return true;
        }
        return false;
    }

    void showAuthScreen() {
        // Show your custom auth UI
        // This could use the SDL2AuthIntegration or your own UI
    }

    void handleAuthEvent(const SDL_Event& event) {
        // Handle authentication UI events
    }

    void handleGameEvent(const SDL_Event& event) {
        if (event.type == SDL_KEYDOWN && event.key.keysym.sym == SDLK_ESCAPE) {
            showGameMenu();
        }
    }

    void showGameMenu() {
        // Show menu with logout option
    }

    void loadUserGameData(const std::string& username) {
        // Load game progress for authenticated user
        std::string userId = authHandler_->getCurrentUserId();
        // Load save files specific to this user
    }

    void saveUserGameData() {
        if (authenticated_) {
            std::string userId = authHandler_->getCurrentUserId();
            // Save game progress
            authHandler_->saveAuthData();
        }
    }

    std::unique_ptr<DegenHF::ECCAuthHandler> authHandler_;
    bool authenticated_ = false;
    std::string currentUsername_;
};
```

### Multi-User Game Server

```cpp
class GameServer {
public:
    void handleClientAuth(int clientId, const std::string& username, const std::string& password) {
        // Create auth handler for this client/session
        auto clientAuth = std::make_unique<DegenHF::ECCAuthHandler>(serverAuthConfig_);

        if (!clientAuth->initialize()) {
            sendAuthResponse(clientId, false, "Server error");
            return;
        }

        auto result = clientAuth->authenticateUser(username, password);
        if (result.success) {
            // Store authenticated client
            authenticatedClients_[clientId] = std::move(clientAuth);
            sendAuthResponse(clientId, true, "Authenticated", result.token);
        } else {
            sendAuthResponse(clientId, false, result.errorMessage);
        }
    }

    void handleClientAction(int clientId, const std::string& token, const std::string& action) {
        auto it = authenticatedClients_.find(clientId);
        if (it == authenticatedClients_.end()) {
            sendError(clientId, "Not authenticated");
            return;
        }

        // Verify token
        auto tokenOpt = it->second->verifyToken(token);
        if (!tokenOpt) {
            sendError(clientId, "Invalid token");
            return;
        }

        // Process authenticated action
        processGameAction(clientId, action);
    }

private:
    DegenHF::AuthConfig serverAuthConfig_;
    std::unordered_map<int, std::unique_ptr<DegenHF::ECCAuthHandler>> authenticatedClients_;
};
```

## Configuration Options

### Authentication Configuration

```cpp
DegenHF::AuthConfig config;

// Security settings
config.hashIterations = 10000;        // Password hashing rounds
config.tokenExpiryHours = 24;         // Token lifetime
config.cacheExpiryMinutes = 5;        // Cache lifetime
config.enableCaching = true;          // Enable token caching
config.maxCacheSize = 1000;          // Maximum cached tokens

// Storage settings
config.userDataPath = "game_auth_data"; // Data storage path
```

### UI Configuration

```cpp
DegenHF::SDL2AuthIntegration::Config uiConfig;

// Window settings
uiConfig.windowWidth = 800;
uiConfig.windowHeight = 600;
uiConfig.windowTitle = "Game Authentication";

// Font settings
uiConfig.fontPath = "assets/fonts/arial.ttf";
uiConfig.fontSize = 24;

// Colors
uiConfig.bgColor = {40, 40, 40, 255};
uiConfig.uiColor = {60, 60, 60, 255};
uiConfig.accentColor = {100, 150, 255, 255};
uiConfig.errorColor = {255, 100, 100, 255};
uiConfig.successColor = {100, 255, 100, 255};

// Auth settings (inherited)
uiConfig.authConfig = authConfig;
```

## API Reference

### ECCAuthHandler Methods

#### Initialization
- `ECCAuthHandler(const AuthConfig& config)` - Constructor
- `bool initialize()` - Initialize the auth handler
- `void shutdown()` - Clean shutdown

#### User Management
- `AuthResult registerUser(const std::string& username, const std::string& password)` - Register new user
- `AuthResult authenticateUser(const std::string& username, const std::string& password)` - Authenticate user
- `void logout()` - Logout current user

#### Token Management
- `std::optional<AuthToken> verifyToken(const std::string& token)` - Verify authentication token
- `std::optional<AuthToken> createToken(const std::string& userId, const std::string& username)` - Create new token
- `bool invalidateToken(const std::string& tokenId)` - Invalidate token

#### Session Management
- `std::string createSession(const std::string& userId)` - Create user session
- `std::optional<UserSession> getSession(const std::string& sessionId)` - Get session info
- `bool invalidateSession(const std::string& sessionId)` - Invalidate session
- `void cleanupExpiredSessions()` - Clean up expired sessions

#### State Queries
- `bool isUserLoggedIn() const` - Check if user is logged in
- `std::string getCurrentUserId() const` - Get current user ID
- `std::string getCurrentUsername() const` - Get current username

#### Data Persistence
- `bool saveAuthData()` - Save authentication data
- `bool loadAuthData()` - Load authentication data

### SDL2AuthIntegration Methods

#### Initialization
- `SDL2AuthIntegration(const Config& config)` - Constructor
- `bool initialize()` - Initialize SDL2 and UI
- `void shutdown()` - Clean shutdown
- `bool run()` - Run main UI loop

#### Authentication State
- `bool isAuthenticated() const` - Check authentication status
- `std::string getCurrentUsername() const` - Get authenticated username
- `std::string getCurrentUserId() const` - Get authenticated user ID

#### UI Management
- `void showLoginScreen()` - Show login screen
- `void showRegisterScreen()` - Show registration screen
- `void showLoggedInScreen()` - Show logged-in screen
- `void showError(const std::string& message)` - Show error message

#### Event Callbacks
- `void setOnLoginSuccess(std::function<void(const std::string&)> callback)`
- `void setOnRegisterSuccess(std::function<void(const std::string&)> callback)`
- `void setOnLogout(std::function<void()> callback)`
- `void setOnQuit(std::function<void()> callback)`

#### SDL Access
- `SDL_Window* getWindow() const` - Get SDL window
- `SDL_Renderer* getRenderer() const` - Get SDL renderer

## Testing

### Running Tests

```bash
# Build tests
cd build
make sdl2_auth_tests

# Run tests
./tests/sdl2_auth_tests
```

### Running Examples

```bash
# Build example
make sdl2_auth_example

# Run example
./examples/sdl2_auth_example
```

## Security Features

- **ECC Cryptography**: secp256k1 curve with ECDSA signatures
- **PBKDF2 Password Hashing**: Configurable iterations for password security
- **Token Expiration**: Automatic token invalidation
- **Session Security**: Unique session IDs with activity tracking
- **Thread Safety**: Mutex-protected concurrent operations
- **Input Validation**: Comprehensive input sanitization
- **Secure Storage**: JSON-based data persistence with proper encoding

## Performance Considerations

### Benchmarks (Approximate)
- **Initialization**: ~100-200ms
- **User Registration**: ~300-600ms (depends on hash iterations)
- **User Authentication**: ~200-500ms
- **Token Verification**: ~5-20ms (cached), ~50-100ms (uncached)
- **Session Operations**: ~1-10ms

### Optimizations
- **Token Caching**: LRU cache for frequently verified tokens
- **Async Operations**: Non-blocking cryptographic operations
- **Efficient Storage**: Optimized JSON serialization
- **Memory Management**: Automatic resource cleanup
- **Thread Safety**: Minimal lock contention

## Troubleshooting

### Build Issues

- **Missing Dependencies**: Ensure all required libraries are installed
- **CMake Errors**: Check CMake version (3.16+) and dependency paths
- **OpenSSL Issues**: Ensure OpenSSL development headers are available
- **SDL2 Not Found**: Verify SDL2 installation and pkg-config setup

### Runtime Issues

- **Font Loading Failed**: Provide a valid TTF font file path
- **Authentication Failed**: Check user data path permissions
- **UI Not Responding**: Ensure SDL2 event loop is properly integrated
- **Memory Issues**: Check for proper cleanup of SDL resources

### Common Errors

- **"Failed to initialize auth handler"**: Check OpenSSL installation
- **"Font loading failed"**: Verify font file exists and path is correct
- **"Registration failed"**: Check username/password requirements
- **"Token expired"**: Tokens expire after configured hours

## Best Practices

### 1. Initialization
- Initialize auth handler early in application startup
- Handle initialization failures gracefully
- Use appropriate configuration for your security needs

### 2. User Experience
- Provide clear feedback for authentication operations
- Implement proper error handling and user messaging
- Consider auto-login for returning users

### 3. Security
- Use strong passwords and appropriate hash iterations
- Implement proper session management
- Regularly cleanup expired sessions and tokens

### 4. Performance
- Enable caching for better performance
- Use appropriate cache sizes for your application
- Consider async authentication for UI responsiveness

### 5. Data Management
- Implement proper save/load cycles
- Backup user data regularly
- Handle data corruption gracefully

### 6. Integration
- Integrate authentication early in development
- Plan for authenticated and unauthenticated states
- Consider user data segregation by user ID

## Examples

See the `examples/` directory for complete working examples:

- **main.cpp**: Basic SDL2 UI integration example
- Shows both UI integration and direct API usage
- Includes game integration patterns

## Contributing

1. Follow the existing code style and patterns
2. Add tests for new functionality
3. Update documentation accordingly
4. Ensure thread safety for new features
5. Test on multiple platforms

## License

This implementation is part of the DegenHF framework. See main project license for details.

## Future Enhancements

- **Enhanced UI**: More customizable UI components
- **Network Support**: Server-client authentication
- **OAuth Integration**: Social login support
- **Multi-Factor Auth**: Additional security layers
- **Database Backend**: SQL database integration
- **Cloud Sync**: Cross-device authentication sync