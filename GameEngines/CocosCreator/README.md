# DegenHF ECC Authentication for Cocos Creator

This directory contains the Cocos Creator integration for DegenHF's ECC-based authentication system, providing blockchain-grade security for Cocos Creator games.

## Features

- **ECC Cryptography**: JavaScript implementation of secp256k1 elliptic curve cryptography
- **Hybrid Password Hashing**: PBKDF2 with SHA-256 for secure password storage
- **JWT-like Token System**: Secure authentication tokens with expiration
- **Session Management**: Persistent sessions across game restarts
- **Cocos Creator Integration**: Native component system integration
- **Async Operations**: Promise-based asynchronous authentication
- **Cross-Platform**: Works on all Cocos Creator supported platforms

## Directory Structure

```
CocosCreator/
├── assets/
│   ├── scenes/
│   │   └── AuthDemoScene.js      # Sample scene configuration
│   ├── scripts/
│   │   ├── DegenHF/
│   │   │   ├── ECCAuthHandler.js # Core ECC authentication logic
│   │   │   └── AuthExtension.js  # Cocos Creator component wrapper
│   │   └── AuthDemo.js           # Sample authentication script
│   ├── prefabs/                  # (Optional) Prefab components
│   └── resources/                # (Optional) UI resources
```

## Installation

### Method 1: Copy to Project

1. Copy the `assets/scripts/DegenHF/` directory to your Cocos Creator project's `assets/scripts/` folder
2. Copy the `assets/scenes/` directory to your project's `assets/scenes/` folder (optional)
3. Copy the `assets/scripts/AuthDemo.js` to your project's scripts folder (optional)

### Method 2: Import as Plugin

1. Download the integration files
2. In Cocos Creator, go to **Extension → Extension Manager**
3. Click **Import Extension** and select the downloaded files

## Setup

### 1. Add Scripts to Project

1. Open your Cocos Creator project
2. Copy the DegenHF scripts to `assets/scripts/DegenHF/`
3. The scripts will be automatically loaded by Cocos Creator

### 2. Initialize Authentication

Create a new scene or modify an existing one:

#### Using Component Approach
```javascript
// Attach AuthExtension component to a node
const authNode = new cc.Node('AuthManager');
const authExtension = authNode.addComponent('DegenHFAuthExtension');

// Configure settings
authExtension.hashIterations = 10000;
authExtension.tokenExpiryHours = 24;
authExtension.userDataPath = 'MyGameAuth';

// Initialize
await authExtension.init();
```

#### Using Direct Script Approach
```javascript
const { DegenHF } = require('DegenHF');

// Create auth handler
const authHandler = new DegenHF.ECCAuthHandler({
    hashIterations: 10000,
    tokenExpiryHours: 24,
    userDataPath: 'MyGameAuth'
});

// Initialize
const success = await authHandler.initialize();
if (success) {
    console.log('Authentication system ready!');
}
```

## Basic Usage

### User Registration

#### Using Component
```javascript
// Register a new user
authExtension.registerUser('username', 'password123', (success, userId, message) => {
    if (success) {
        console.log('Registration successful! User ID:', userId);
    } else {
        console.log('Registration failed:', message);
    }
});
```

#### Using Direct Script
```javascript
// Register a new user
const result = await authHandler.registerUser('username', 'password123');
if (result.success) {
    console.log('Registration successful! User ID:', result.userId);
} else {
    console.log('Registration failed:', result.errorMessage);
}
```

### User Login

#### Using Component
```javascript
// Login user
authExtension.loginUser('username', 'password123', (success, token, userId, username, message) => {
    if (success) {
        console.log('Login successful! Welcome', username);
        // Store token for session management
        cc.sys.localStorage.setItem('auth_token', token);
    } else {
        console.log('Login failed:', message);
    }
});
```

#### Using Direct Script
```javascript
// Login user
const result = await authHandler.authenticateUser('username', 'password123');
if (result.success) {
    console.log('Login successful! Welcome', result.username);
    // Store token for session management
} else {
    console.log('Login failed:', result.errorMessage);
}
```

### Check Login Status

#### Using Component
```javascript
if (authExtension.isLoggedIn()) {
    const username = authExtension.getCurrentUsername();
    const userId = authExtension.getCurrentUserId();
    console.log('User', username, 'is logged in (ID:', userId, ')');
}
```

#### Using Direct Script
```javascript
if (authHandler.isUserLoggedIn()) {
    const username = authHandler.getCurrentUsername();
    const userId = authHandler.getCurrentUserId();
    console.log('User', username, 'is logged in (ID:', userId, ')');
}
```

### Token Verification

#### Using Component
```javascript
// Verify stored token
const storedToken = cc.sys.localStorage.getItem('auth_token');
authExtension.verifyToken(storedToken, (valid, message) => {
    if (valid) {
        console.log('Token is valid');
    } else {
        console.log('Token invalid:', message);
    }
});
```

#### Using Direct Script
```javascript
// Verify stored token
const result = await authHandler.verifyToken(storedToken);
if (result.valid) {
    console.log('Token is valid');
} else {
    console.log('Token invalid:', result.errorMessage);
}
```

### Session Management

#### Using Component
```javascript
// Create a session
authExtension.createSession((sessionId) => {
    if (sessionId) {
        console.log('Session created:', sessionId);
        // Store sessionId for later use
    }
});

// Get session info
authExtension.getSessionInfo(sessionId, (valid, userId, username) => {
    if (valid) {
        console.log('Session valid for user:', username);
    }
});
```

#### Using Direct Script
```javascript
// Create a session
const sessionId = authHandler.createSession(userId);

// Get session info
const sessionInfo = await authHandler.getSession(sessionId);
if (sessionInfo.valid) {
    console.log('Session valid for user:', sessionInfo.username);
}
```

### Logout

#### Using Component
```javascript
authExtension.logoutUser((success, message) => {
    if (success) {
        console.log('Logged out successfully');
    } else {
        console.log('Logout failed:', message);
    }
});
```

#### Using Direct Script
```javascript
authHandler.logout();
console.log('Logged out successfully');
```

## Configuration Options

The authentication system can be customized with various options:

```javascript
const config = {
    hashIterations: 10000,        // Password hashing rounds
    tokenExpiryHours: 24,         // Token lifetime in hours
    cacheExpiryMinutes: 5,        // Cache lifetime in minutes
    userDataPath: 'MyGameAuth'    // Custom data storage path
};

// Using component
authExtension.init(config);

// Using direct script
const authHandler = new DegenHF.ECCAuthHandler(config);
```

## Demo Scene

The included demo scene shows a complete working example:

1. **Registration**: Create new user accounts
2. **Login**: Authenticate existing users
3. **Session Management**: Create and verify sessions
4. **Logout**: Properly end user sessions

To use the demo:

1. Copy `AuthDemoScene.js` to your `assets/scenes/` folder
2. Copy `AuthDemo.js` to your `assets/scripts/` folder
3. Create a new scene in Cocos Creator
4. Add the AuthDemo component to the Canvas node
5. Set up the UI references in the component properties
6. Run the scene to see the authentication system in action

## Event System

The component approach supports event-driven programming:

```javascript
// Listen for authentication events
cc.systemEvent.on('degenhf:register_completed', (success, userId, message) => {
    console.log('Register event:', success, userId, message);
});

cc.systemEvent.on('degenhf:login_completed', (success, token, userId, username, message) => {
    console.log('Login event:', success, token, userId, username, message);
});

cc.systemEvent.on('degenhf:verify_completed', (valid, message) => {
    console.log('Verify event:', valid, message);
});
```

## Security Features

- **ECC Cryptography**: JavaScript implementation of secp256k1 curve
- **PBKDF2 Password Hashing**: Configurable iterations for password security
- **Token Expiration**: Automatic token invalidation
- **Session Security**: Secure session handling with unique IDs
- **Data Encryption**: Sensitive data stored securely in localStorage

## Platform Support

- **Web**: Full support (browsers with crypto API)
- **Android**: Full support via Cocos Creator
- **iOS**: Full support via Cocos Creator
- **Desktop**: Full support (Windows, macOS, Linux)
- **Mini Games**: Limited support (depends on platform crypto APIs)

## Best Practices

### 1. Initialize Early
Call `init()` when your game starts, before any auth operations.

### 2. Handle Promises
Always use `await` or `.then()` with async operations.

### 3. Store Tokens Securely
Use `cc.sys.localStorage` for storing sensitive tokens.

### 4. Validate Input
Check username/password requirements before calling auth methods.

### 5. Error Handling
Always check return values and handle errors gracefully.

### 6. Session Management
Use sessions for temporary authentication needs.

### 7. Cleanup
Call `logout()` and `saveAuthState()` when appropriate.

## Example Game Integration

Here's how you might integrate authentication into a typical Cocos Creator game:

```javascript
// GameManager.js
cc.Class({
    extends: cc.Component,

    properties: {
        authExtension: {
            default: null,
            type: require('DegenHFAuthExtension')
        }
    },

    onLoad() {
        this.initializeAuth();
    },

    async initializeAuth() {
        // Initialize authentication
        const success = await this.authExtension.init({
            userDataPath: 'MyAwesomeGame'
        });

        if (success) {
            // Try to auto-login
            await this.tryAutoLogin();
        }
    },

    async tryAutoLogin() {
        // Load saved auth state
        await this.authExtension.loadAuthState();

        if (this.authExtension.isLoggedIn()) {
            this.showMainMenu();
        } else {
            this.showLoginScreen();
        }
    },

    showLoginScreen() {
        // Load login scene
        cc.director.loadScene('LoginScene');
    },

    showMainMenu() {
        // Load main menu
        cc.director.loadScene('MainMenuScene');
    },

    // Called when login is successful
    onLoginSuccess(userData) {
        this.currentUser = userData;
        this.showMainMenu();
    },

    // Called when logout occurs
    onLogout() {
        this.currentUser = null;
        this.showLoginScreen();
    }
});
```

## API Reference

### ECCAuthHandler Methods
- `initialize()` → Promise<boolean>
- `registerUser(username, password)` → Promise<Object>
- `authenticateUser(username, password)` → Promise<Object>
- `verifyToken(token)` → Promise<Object>
- `createSession(userId)` → string
- `getSession(sessionId)` → Promise<Object>
- `isUserLoggedIn()` → boolean
- `getCurrentUserId()` → string
- `getCurrentUsername()` → string
- `logout()` → void
- `saveAuthData()` → Promise<void>
- `loadAuthData()` → Promise<void>

### AuthExtension Methods
- `init(config)` → Promise<boolean>
- `registerUser(username, password, callback)` → void
- `loginUser(username, password, callback)` → void
- `logoutUser(callback)` → void
- `isLoggedIn()` → boolean
- `getCurrentUserId()` → string
- `getCurrentUsername()` → string
- `verifyToken(token, callback)` → void
- `createSession(callback)` → void
- `getSessionInfo(sessionId, callback)` → void
- `saveAuthState()` → void
- `loadAuthState()` → Promise<void>

### Events
- `degenhf:register_completed` (success, userId, message)
- `degenhf:login_completed` (success, token, userId, username, message)
- `degenhf:verify_completed` (valid, message)

## Troubleshooting

### Build Issues

- **Script Loading Errors**: Ensure scripts are in the correct folder structure
- **Component Not Found**: Check that AuthExtension.js is properly loaded
- **Crypto API Issues**: Some platforms may not support full crypto APIs

### Runtime Issues

- **Initialization Failed**: Check console for detailed error messages
- **Login Failed**: Verify username/password and check error messages
- **Token Invalid**: Check token expiration settings

### Common Errors

- **"Extension not initialized"**: Call `init()` before using auth methods
- **"User not found"**: User doesn't exist or data corrupted
- **"Invalid password"**: Wrong password entered
- **"Token expired"**: Token has exceeded expiry time

## Performance Considerations

- **Async Operations**: All cryptographic operations are asynchronous
- **Local Storage**: Data persistence uses efficient localStorage
- **Memory Management**: Automatic cleanup on component destruction
- **Caching**: Token and session caching for improved performance

## Limitations

- **Crypto Strength**: JavaScript ECC implementation is simplified for compatibility
- **Platform Support**: Some platforms may have limited crypto API support
- **Storage Security**: localStorage is not encrypted (use platform-specific secure storage in production)

## Contributing

Contributions are welcome! Please:

1. Test your changes with the demo scene
2. Follow Cocos Creator coding conventions
3. Update documentation for any new features
4. Ensure cross-platform compatibility

## License

This implementation is part of the DegenHF framework. See main project license for details.

## Support

For issues or questions:

1. Check the demo scene implementation
2. Review error messages in the Cocos Creator console
3. Verify configuration settings
4. Test with the provided demo scene

## Future Enhancements

- **Enhanced Crypto**: Integration with native crypto libraries
- **Database Support**: Server-side authentication storage
- **OAuth Integration**: Social login support
- **Multi-Factor Auth**: Additional security layers
- **Offline Support**: Cached authentication for offline play