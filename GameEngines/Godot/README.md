# DegenHF ECC Authentication for Godot

This directory contains the Godot integration for DegenHF's ECC-based authentication system, providing blockchain-grade security for Godot games.

## Features

- **ECC secp256k1 Cryptography**: Industry-standard elliptic curve cryptography
- **Hybrid Password Hashing**: PBKDF2 with SHA-256 for secure password storage
- **JWT-like Token System**: Secure authentication tokens with expiration
- **Session Management**: Persistent sessions across game restarts
- **Cross-Language Support**: C# implementation with GDScript wrapper
- **Thread-Safe Operations**: Asynchronous operations with proper callbacks
- **Godot Integration**: Native Godot Node system integration

## Directory Structure

```
Godot/
├── addons/DegenHF/
│   ├── ECCAuthHandler.cs      # Core ECC authentication logic (C#)
│   ├── AuthExtension.cs       # Godot C# extension wrapper
│   └── DegenHFAuth.gd         # GDScript wrapper for easy use
├── demo/
│   ├── scenes/
│   │   └── AuthDemo.tscn      # Sample authentication scene
│   └── scripts/
│       └── AuthDemo.gd        # Sample authentication script
└── plugin.cfg                 # Godot plugin configuration
```

## Installation

### Method 1: Copy to Project

1. Copy the `addons/DegenHF/` directory to your Godot project's `addons/` folder
2. Copy the `demo/` directory to your project root (optional, for reference)
3. Enable the plugin in Project → Project Settings → Plugins

### Method 2: Git Submodule

```bash
git submodule add https://github.com/degenwithheart/DegenHF-The-Next-Gen-Authentication-Encryption-Framework.git addons/DegenHF
```

## Setup

### 1. Enable the Plugin

1. Open your Godot project
2. Go to **Project → Project Settings → Plugins**
3. Find "DegenHF Auth" and check the "Enable" box

### 2. Initialize Authentication

Add this to your main scene or autoload script:

#### GDScript
```gdscript
extends Node

var auth = null

func _ready():
    # Load the authentication system
    auth = preload("res://addons/DegenHF/DegenHFAuth.gd").new()
    add_child(auth)

    # Initialize with default config
    if auth.initialize():
        print("Authentication system ready!")
    else:
        print("Failed to initialize authentication")
```

#### C#
```csharp
using Godot;
using DegenHF.Godot;

public class MainScene : Node
{
    private AuthExtension auth;

    public override void _Ready()
    {
        auth = AuthExtension.GetInstance();
        AddChild(auth);

        var config = new ECC.AuthHandler.Config();
        if (auth.Init(config))
        {
            GD.Print("Authentication system ready!");
        }
    }
}
```

## Basic Usage

### User Registration

#### GDScript
```gdscript
# Register a new user
auth.register_user("username", "password123", funcref(self, "_on_register_complete"))

func _on_register_complete(success, user_id, message):
    if success:
        print("Registration successful! User ID: ", user_id)
    else:
        print("Registration failed: ", message)
```

#### C#
```csharp
// Register a new user
auth.RegisterUser("username", "password123", (success, userId, message) => {
    if (success) {
        GD.Print($"Registration successful! User ID: {userId}");
    } else {
        GD.Print($"Registration failed: {message}");
    }
});
```

### User Login

#### GDScript
```gdscript
# Login user
auth.login_user("username", "password123", funcref(self, "_on_login_complete"))

func _on_login_complete(success, token, user_id, username, message):
    if success:
        print("Login successful! Welcome ", username)
        # Store token for session management
        GameData.auth_token = token
    else:
        print("Login failed: ", message)
```

#### C#
```csharp
// Login user
auth.LoginUser("username", "password123", (success, token, userId, username, message) => {
    if (success) {
        GD.Print($"Login successful! Welcome {username}");
        // Store token for session management
    } else {
        GD.Print($"Login failed: {message}");
    }
});
```

### Check Login Status

#### GDScript
```gdscript
if auth.is_logged_in():
    var username = auth.get_current_username()
    var user_id = auth.get_current_user_id()
    print("User ", username, " is logged in (ID: ", user_id, ")")
```

#### C#
```csharp
if (auth.IsLoggedIn()) {
    string username = auth.GetCurrentUsername();
    string userId = auth.GetCurrentUserId();
    GD.Print($"User {username} is logged in (ID: {userId})");
}
```

### Token Verification

#### GDScript
```gdscript
# Verify stored token
auth.verify_token(stored_token, funcref(self, "_on_verify_complete"))

func _on_verify_complete(valid, message):
    if valid:
        print("Token is valid")
    else:
        print("Token invalid: ", message)
```

#### C#
```csharp
// Verify stored token
auth.VerifyToken(storedToken, (valid, message) => {
    if (valid) {
        GD.Print("Token is valid");
    } else {
        GD.Print($"Token invalid: {message}");
    }
});
```

### Session Management

#### GDScript
```gdscript
# Create a session
auth.create_session(funcref(self, "_on_session_created"))

func _on_session_created(session_id):
    if session_id:
        print("Session created: ", session_id)
        # Store session_id for later use

# Get session info
auth.get_session_info(session_id, funcref(self, "_on_session_info"))

func _on_session_info(valid, user_id, username):
    if valid:
        print("Session valid for user: ", username)
```

#### C#
```csharp
// Create a session
auth.CreateSession((sessionId) => {
    if (!string.IsNullOrEmpty(sessionId)) {
        GD.Print($"Session created: {sessionId}");
    }
});

// Get session info
auth.GetSessionInfo(sessionId, (valid, userId, username) => {
    if (valid) {
        GD.Print($"Session valid for user: {username}");
    }
});
```

### Logout

#### GDScript
```gdscript
auth.logout_user(funcref(self, "_on_logout_complete"))

func _on_logout_complete(success, message):
    if success:
        print("Logged out successfully")
    else:
        print("Logout failed: ", message)
```

#### C#
```csharp
auth.LogoutUser((success, message) => {
    if (success) {
        GD.Print("Logged out successfully");
    } else {
        GD.Print($"Logout failed: {message}");
    }
});
```

## Configuration Options

The authentication system can be customized with various options:

```gdscript
var config = {
    "hash_iterations": 10000,        # Password hashing rounds
    "token_expiry_hours": 24,        # Token lifetime in hours
    "cache_expiry_minutes": 5,       # Cache lifetime in minutes
    "user_data_path": "user://GameAuth"  # Custom data storage path
}

auth.initialize(config)
```

## Demo Scene

The included demo scene (`demo/scenes/AuthDemo.tscn`) shows a complete working example:

1. **Registration**: Create new user accounts
2. **Login**: Authenticate existing users
3. **Session Management**: Create and verify sessions
4. **Logout**: Properly end user sessions

To use the demo:

1. Copy `demo/scenes/AuthDemo.tscn` to your project
2. Set it as your main scene or instance it in your game
3. Run the project to see the authentication system in action

## Security Features

- **ECC Cryptography**: secp256k1 curve with secure key generation
- **PBKDF2 Password Hashing**: Configurable iterations for password security
- **Token Expiration**: Automatic token invalidation
- **Session Security**: Secure session handling with unique IDs
- **Data Encryption**: Sensitive data stored securely in JSON format

## Platform Support

- **Windows**: Full support
- **macOS**: Full support
- **Linux**: Full support
- **Android**: Full support (with C# export)
- **iOS**: Full support (with C# export)
- **HTML5**: Limited support (file system restrictions)

## Best Practices

### 1. Initialize Early
Call `initialize()` when your game starts, before any auth operations.

### 2. Handle Callbacks
Always provide callback functions for async operations.

### 3. Store Tokens Securely
Use Godot's built-in encryption for storing sensitive tokens.

### 4. Validate Input
Check username/password requirements before calling auth methods.

### 5. Error Handling
Always check return values and handle errors gracefully.

### 6. Session Management
Use sessions for temporary authentication needs.

### 7. Cleanup
Call `cleanup()` when the authentication system is no longer needed.

## Example Game Integration

Here's how you might integrate authentication into a typical Godot game:

```gdscript
extends Node

var auth = null
var current_user = null

func _ready():
    # Initialize auth system
    auth = preload("res://addons/DegenHF/DegenHFAuth.gd").new()
    add_child(auth)

    if auth.initialize():
        # Try to auto-login
        if auth.auto_login():
            show_main_menu()
        else:
            show_login_screen()

func show_login_screen():
    # Show login/register UI
    var login_scene = preload("res://scenes/LoginScreen.tscn").instance()
    add_child(login_scene)

    # Connect to login signals
    login_scene.connect("login_requested", self, "_on_login_requested")
    login_scene.connect("register_requested", self, "_on_register_requested")

func _on_login_requested(username, password):
    auth.login_user(username, password, funcref(self, "_on_auth_result"))

func _on_register_requested(username, password):
    auth.register_user(username, password, funcref(self, "_on_auth_result"))

func _on_auth_result(success, token, user_id, username, message):
    if success:
        current_user = {
            "id": user_id,
            "username": username,
            "token": token
        }
        show_main_menu()
    else:
        # Show error message
        show_error(message)

func show_main_menu():
    # Load main game menu
    var menu = preload("res://scenes/MainMenu.tscn").instance()
    add_child(menu)

func _notification(what):
    if what == NOTIFICATION_WM_QUIT_REQUEST:
        # Save auth state before quitting
        auth.save_auth_state()
```

## Troubleshooting

### Build Issues

- **C# Compilation Errors**: Ensure Godot is configured for C# projects
- **Missing Dependencies**: Check that .NET Framework is properly installed
- **Plugin Not Loading**: Verify plugin.cfg is in the correct location

### Runtime Issues

- **Initialization Failed**: Check file system permissions for user data
- **Login Failed**: Verify username/password and check logs
- **Token Invalid**: Check token expiration settings

### Common Errors

- **"Extension not initialized"**: Call `initialize()` before using auth methods
- **"User not found"**: User doesn't exist or data corrupted
- **"Invalid password"**: Wrong password entered
- **"Token expired"**: Token has exceeded expiry time

## API Reference

### GDScript API

#### Methods
- `initialize(config)` → bool
- `register_user(username, password, callback)` → void
- `login_user(username, password, callback)` → void
- `logout_user(callback)` → void
- `is_logged_in()` → bool
- `get_current_user_id()` → String
- `get_current_username()` → String
- `verify_token(token, callback)` → void
- `create_session(callback)` → void
- `get_session_info(session_id, callback)` → void
- `save_auth_state()` → void
- `load_auth_state()` → void
- `cleanup()` → void

#### Signals
- `register_completed(success, user_id, message)`
- `login_completed(success, token, user_id, username, message)`
- `verify_completed(valid, message)`

### C# API

See `AuthExtension.cs` for the complete C# API documentation.

## License

This implementation is part of the DegenHF framework. See main project license for details.

## Support

For issues or questions:

1. Check the demo scene implementation
2. Review error messages in the Godot console
3. Verify configuration settings
4. Test with the provided demo scene

## Contributing

Contributions are welcome! Please:

1. Test your changes with the demo scene
2. Follow Godot's C# coding conventions
3. Update documentation for any new features
4. Ensure cross-platform compatibility