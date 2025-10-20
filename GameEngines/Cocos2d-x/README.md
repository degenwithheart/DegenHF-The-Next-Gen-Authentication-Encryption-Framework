# DegenHF ECC Authentication for Cocos2d-x

This directory contains the Cocos2d-x integration for DegenHF's ECC-based authentication system, providing blockchain-grade security for Cocos2d-x games.

## Features

- **ECC secp256k1 Cryptography**: Industry-standard elliptic curve cryptography
- **Hybrid Password Hashing**: Argon2+BLAKE3 for secure password storage
- **JWT-like Token System**: Secure authentication tokens with expiration
- **Session Management**: Persistent sessions across game restarts
- **Thread-Safe Operations**: Background processing with main-thread callbacks
- **Cross-Platform**: Works on all Cocos2d-x supported platforms

## Directory Structure

```
Cocos2d-x/
├── Classes/DegenHF/
│   ├── ECCAuthHandler.h/.cpp      # Core ECC authentication logic
│   └── AuthSampleScene.h/.cpp     # Sample implementation
└── cocos2d/extensions/DegenHF/
    └── AuthExtension.h/.cpp       # Cocos2d-x specific extension
```

## Integration Steps

### 1. Add to Your Project

Copy the `Classes/DegenHF/` and `cocos2d/extensions/DegenHF/` directories to your Cocos2d-x project's source directories.

### 2. Include Headers

Add the following includes to your source files:

```cpp
#include "DegenHF/AuthExtension.h"
#include "DegenHF/AuthSampleScene.h"  // For sample implementation
```

### 3. Initialize the Extension

Initialize the authentication extension in your `AppDelegate.cpp` or main scene:

```cpp
#include "DegenHF/AuthExtension.h"

// In your initialization code
auto auth = DegenHF::Cocos2dx::AuthExtension::getInstance();
DegenHF::ECC::AuthHandler::Config config;
config.userDataPath = "GameAuth";  // Custom path for user data
config.hashIterations = 10000;    // Password hashing rounds
config.tokenExpiryHours = 24;     // Token lifetime

if (!auth->init(config)) {
    CCLOG("Failed to initialize DegenHF Auth");
}
```

### 4. Basic Usage

#### User Registration

```cpp
auth->registerUser("username", "password",
    [](bool success, const std::string& userId, const std::string& message) {
        if (success) {
            CCLOG("Registration successful! User ID: %s", userId.c_str());
        } else {
            CCLOG("Registration failed: %s", message.c_str());
        }
    });
```

#### User Login

```cpp
auth->loginUser("username", "password",
    [](bool success, const std::string& token, const std::string& userId,
       const std::string& username, const std::string& message) {
        if (success) {
            CCLOG("Login successful! Token: %s", token.c_str());
            // Store token for session management
        } else {
            CCLOG("Login failed: %s", message.c_str());
        }
    });
```

#### Check Login Status

```cpp
if (auth->isLoggedIn()) {
    std::string username = auth->getCurrentUsername();
    std::string userId = auth->getCurrentUserId();
    CCLOG("User %s is logged in (ID: %s)", username.c_str(), userId.c_str());
}
```

#### Token Verification

```cpp
auth->verifyToken(storedToken,
    [](bool valid, const std::string& message) {
        if (valid) {
            CCLOG("Token is valid");
        } else {
            CCLOG("Token invalid: %s", message.c_str());
        }
    });
```

#### Session Management

```cpp
// Create a session
auth->createSession([](const std::string& sessionId) {
    if (!sessionId.empty()) {
        // Store sessionId for later use
        CCLOG("Session created: %s", sessionId.c_str());
    }
});

// Get session info
auth->getSessionInfo(sessionId,
    [](bool valid, const std::string& userId, const std::string& username) {
        if (valid) {
            CCLOG("Session valid for user: %s", username.c_str());
        }
    });
```

#### Logout

```cpp
auth->logoutUser([](bool success, const std::string& message) {
    if (success) {
        CCLOG("Logged out successfully");
    }
});
```

## Configuration Options

The `ECC::AuthHandler::Config` struct allows customization:

```cpp
struct Config {
    int hashIterations = 10000;           // Password hashing rounds
    int tokenExpiryHours = 24;            // Token lifetime in hours
    int cacheExpiryMinutes = 5;           // Cache lifetime in minutes
    std::string userDataPath = "UserData"; // Path for storing user data
};
```

## Security Features

- **ECC Key Pairs**: Each user gets unique secp256k1 key pairs
- **PBKDF2 Password Hashing**: Configurable rounds for password security
- **Token Expiration**: Automatic token invalidation
- **Session Management**: Secure session handling
- **Data Encryption**: Sensitive data stored securely

## Sample Implementation

See `AuthSampleScene.h/.cpp` for a complete working example that demonstrates:

- User interface for login/registration
- Real-time status updates
- Error handling
- Session verification

To use the sample scene:

```cpp
#include "DegenHF/AuthSampleScene.h"

// In your code
auto scene = AuthSampleScene::createScene();
Director::getInstance()->replaceScene(scene);
```

## Dependencies

This implementation requires:

- OpenSSL (for ECC cryptography)
- RapidJSON (for data serialization)
- Cocos2d-x 3.17+ (for platform integration)

## Platform Support

- iOS
- Android
- Windows
- macOS
- Linux

## Error Handling

All operations return detailed error messages. Common error scenarios:

- "Extension not initialized": Call `init()` first
- "User already exists": Username taken during registration
- "User not found": Invalid username during login
- "Invalid password": Wrong password during login
- "Invalid or expired token": Token verification failed

## Best Practices

1. **Initialize Early**: Call `init()` before any auth operations
2. **Handle Callbacks**: Always provide callback functions for async operations
3. **Store Tokens Securely**: Use platform-specific secure storage for tokens
4. **Validate Input**: Check username/password requirements before calling auth methods
5. **Error Handling**: Always check return values and handle errors gracefully
6. **Session Management**: Use sessions for temporary authentication needs

## Troubleshooting

### Build Issues

- Ensure OpenSSL headers are available
- Check that RapidJSON is properly included
- Verify Cocos2d-x version compatibility

### Runtime Issues

- Check log output for detailed error messages
- Verify file system permissions for user data storage
- Ensure proper OpenSSL library linking

### Authentication Issues

- Check token expiration settings
- Verify password requirements
- Confirm user data directory permissions

## License

This implementation is part of the DegenHF framework. See main project license for details.

## Support

For issues or questions:

1. Check the sample implementation
2. Review error messages in logs
3. Verify configuration settings
4. Test with the provided sample scene