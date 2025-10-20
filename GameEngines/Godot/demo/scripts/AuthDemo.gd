# DegenHF Authentication Demo Scene
# Demonstrates how to integrate ECC authentication into Godot games

extends Control

# UI References
onready var status_label = $VBoxContainer/StatusLabel
onready var username_field = $VBoxContainer/UsernameField
onready var password_field = $VBoxContainer/PasswordField
onready var login_button = $VBoxContainer/LoginButton
onready var register_button = $VBoxContainer/RegisterButton
onready var logout_button = $VBoxContainer/LogoutButton
onready var verify_button = $VBoxContainer/VerifyButton

# Authentication system
var auth: Node = null

func _ready():
    # Initialize authentication system
    auth = preload("res://addons/DegenHF/DegenHFAuth.gd").new()
    add_child(auth)

    # Connect signals
    auth.connect("register_completed", self, "_on_register_completed")
    auth.connect("login_completed", self, "_on_login_completed")
    auth.connect("verify_completed", self, "_on_verify_completed")

    # Connect button signals
    login_button.connect("pressed", self, "_on_login_pressed")
    register_button.connect("pressed", self, "_on_register_pressed")
    logout_button.connect("pressed", self, "_on_logout_pressed")
    verify_button.connect("pressed", self, "_on_verify_pressed")

    # Initialize with custom config
    var config = {
        "hash_iterations": 10000,
        "token_expiry_hours": 24,
        "user_data_path": "user://DegenHFDemo"
    }

    if auth.initialize(config):
        show_message("Authentication system initialized")
        update_ui()
    else:
        show_message("Failed to initialize authentication system")

func _on_login_pressed():
    var username = username_field.text.strip_edges()
    var password = password_field.text.strip_edges()

    if username.empty() or password.empty():
        show_message("Please enter username and password")
        return

    show_message("Logging in...")
    disable_buttons()

    # Create callback function
    var callback = funcref(self, "_on_login_callback")
    auth.login_user(username, password, callback)

func _on_register_pressed():
    var username = username_field.text.strip_edges()
    var password = password_field.text.strip_edges()

    if username.empty() or password.empty():
        show_message("Please enter username and password")
        return

    if password.length() < 6:
        show_message("Password must be at least 6 characters")
        return

    show_message("Registering...")
    disable_buttons()

    # Create callback function
    var callback = funcref(self, "_on_register_callback")
    auth.register_user(username, password, callback)

func _on_logout_pressed():
    auth.logout_user(funcref(self, "_on_logout_callback"))

func _on_verify_pressed():
    # For demo purposes, create a session and verify it
    auth.create_session(funcref(self, "_on_session_created"))

# Callback functions
func _on_register_callback(success: bool, user_id: String, message: String):
    enable_buttons()
    if success:
        clear_fields()
        show_message("Registration successful! You can now login.")
    else:
        show_message("Registration failed: " + message)

func _on_login_callback(success: bool, token: String, user_id: String, username: String, message: String):
    enable_buttons()
    if success:
        clear_fields()
        update_ui()
        show_message("Login successful! Welcome " + username)
    else:
        show_message("Login failed: " + message)

func _on_logout_callback(success: bool, message: String):
    update_ui()
    if success:
        show_message("Logged out successfully")
    else:
        show_message("Logout failed: " + message)

func _on_session_created(session_id: String):
    if session_id.empty():
        show_message("Failed to create session")
        return

    # Get session info
    auth.get_session_info(session_id, funcref(self, "_on_session_info"))

func _on_session_info(valid: bool, user_id: String, username: String):
    if valid:
        show_message("Session valid for user: " + username)
    else:
        show_message("Session invalid")

# UI helper functions
func update_ui():
    var logged_in = auth.is_logged_in()

    if logged_in:
        var username = auth.get_current_username()
        var user_id = auth.get_current_user_id()
        status_label.text = "Logged in as: " + username + "\nID: " + user_id.substr(0, 8) + "..."

        login_button.visible = false
        register_button.visible = false
        logout_button.visible = true
        verify_button.visible = true
    else:
        status_label.text = "Not logged in"

        login_button.visible = true
        register_button.visible = true
        logout_button.visible = false
        verify_button.visible = false

func show_message(message: String):
    status_label.text = message

    # Reset color after 3 seconds
    var timer = get_tree().create_timer(3.0)
    timer.connect("timeout", self, "_reset_status_color")

func clear_fields():
    username_field.text = ""
    password_field.text = ""

func disable_buttons():
    login_button.disabled = true
    register_button.disabled = true
    logout_button.disabled = true
    verify_button.disabled = true

func enable_buttons():
    login_button.disabled = false
    register_button.disabled = false
    logout_button.disabled = false
    verify_button.disabled = false

func _reset_status_color():
    update_ui()

# Cleanup
func _exit_tree():
    if auth:
        auth.cleanup()