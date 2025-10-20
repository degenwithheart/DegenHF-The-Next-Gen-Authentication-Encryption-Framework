# DegenHF Godot Authentication Extension
# Provides easy-to-use ECC authentication for Godot games

extends Node

class_name DegenHFAuth

# Signals for authentication events
signal register_completed(success, user_id, message)
signal login_completed(success, token, user_id, username, message)
signal verify_completed(valid, message)

# Internal reference to the C# extension
var _auth_extension: Node = null
var _initialized: bool = false

func _ready():
    # Try to get the C# extension
    _auth_extension = get_node_or_null("/root/DegenHFAuthExtension")
    if _auth_extension == null:
        # Create the C# extension if it doesn't exist
        _auth_extension = load("res://addons/DegenHF/AuthExtension.cs").new()
        _auth_extension.name = "DegenHFAuthExtension"
        get_tree().root.add_child(_auth_extension)

        # Connect signals
        _auth_extension.connect("register_completed", self, "_on_register_completed")
        _auth_extension.connect("login_completed", self, "_on_login_completed")
        _auth_extension.connect("verify_completed", self, "_on_verify_completed")

func _on_register_completed(success: bool, user_id: String, message: String):
    emit_signal("register_completed", success, user_id, message)

func _on_login_completed(success: bool, token: String, user_id: String, username: String, message: String):
    emit_signal("login_completed", success, token, user_id, username, message)

func _on_verify_completed(valid: bool, message: String):
    emit_signal("verify_completed", valid, message)

# Initialize the authentication system
func initialize(config: Dictionary = {}) -> bool:
    if _auth_extension == null:
        push_error("DegenHF Auth Extension not found")
        return false

    # Convert GDScript dictionary to C# config
    var csharp_config = _auth_extension.get_script().Config.new()

    if config.has("hash_iterations"):
        csharp_config.HashIterations = config.hash_iterations
    if config.has("token_expiry_hours"):
        csharp_config.TokenExpiryHours = config.token_expiry_hours
    if config.has("cache_expiry_minutes"):
        csharp_config.CacheExpiryMinutes = config.cache_expiry_minutes
    if config.has("user_data_path"):
        csharp_config.UserDataPath = config.user_data_path

    _initialized = _auth_extension.Init(csharp_config)
    return _initialized

# Register a new user
func register_user(username: String, password: String, callback: FuncRef = null):
    if not _initialized:
        if callback:
            callback.call_func(false, "", "Extension not initialized")
        return

    _auth_extension.RegisterUser(username, password, callback)

# Login user
func login_user(username: String, password: String, callback: FuncRef = null):
    if not _initialized:
        if callback:
            callback.call_func(false, "", "", "", "Extension not initialized")
        return

    _auth_extension.LoginUser(username, password, callback)

# Logout current user
func logout_user(callback: FuncRef = null):
    if not _initialized:
        if callback:
            callback.call_func(false, "Extension not initialized")
        return

    _auth_extension.LogoutUser(callback)

# Check if user is logged in
func is_logged_in() -> bool:
    if not _initialized:
        return false
    return _auth_extension.IsLoggedIn()

# Get current user ID
func get_current_user_id() -> String:
    if not _initialized:
        return ""
    return _auth_extension.GetCurrentUserId()

# Get current username
func get_current_username() -> String:
    if not _initialized:
        return ""
    return _auth_extension.GetCurrentUsername()

# Verify authentication token
func verify_token(token: String, callback: FuncRef = null):
    if not _initialized:
        if callback:
            callback.call_func(false, "Extension not initialized")
        return

    _auth_extension.VerifyToken(token, callback)

# Create a secure session
func create_session(callback: FuncRef = null):
    if not _initialized:
        if callback:
            callback.call_func("")
        return

    _auth_extension.CreateSession(callback)

# Get session information
func get_session_info(session_id: String, callback: FuncRef = null):
    if not _initialized:
        if callback:
            callback.call_func(false, "", "")
        return

    _auth_extension.GetSessionInfo(session_id, callback)

# Save authentication state
func save_auth_state():
    if _initialized:
        _auth_extension.SaveAuthState()

# Load authentication state
func load_auth_state():
    if _initialized:
        _auth_extension.LoadAuthState()

# Utility functions for common authentication flows

# Auto-login with saved credentials (for demo purposes)
func auto_login() -> bool:
    if not _initialized:
        return false

    load_auth_state()
    return is_logged_in()

# Check token validity and refresh if needed
func validate_session(token: String) -> bool:
    if not _initialized:
        return false

    var result = _auth_extension.GetAuthHandler().VerifyToken(token)
    return result.Valid

# Get user info from token
func get_user_from_token(token: String) -> Dictionary:
    if not _initialized:
        return {}

    var result = _auth_extension.GetAuthHandler().VerifyToken(token)
    if result.Valid:
        return {
            "user_id": result.UserId,
            "username": result.Username
        }
    return {}

# Clean up resources
func cleanup():
    if _auth_extension:
        _auth_extension.queue_free()
        _auth_extension = null
    _initialized = false