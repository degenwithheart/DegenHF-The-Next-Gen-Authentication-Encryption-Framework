// Example Cocos Creator project structure with DegenHF authentication
// This shows how to integrate the authentication system into your game

// Main Game Scene Script (MainGame.js)
cc.Class({
    extends: cc.Component,

    properties: {
        authExtension: {
            default: null,
            type: require('DegenHFAuthExtension')
        },
        loginPanel: {
            default: null,
            type: cc.Node
        },
        gamePanel: {
            default: null,
            type: cc.Node
        },
        usernameInput: {
            default: null,
            type: cc.EditBox
        },
        passwordInput: {
            default: null,
            type: cc.EditBox
        },
        statusLabel: {
            default: null,
            type: cc.Label
        }
    },

    onLoad() {
        this.initializeGame();
    },

    async initializeGame() {
        // Initialize authentication system
        const success = await this.authExtension.init({
            hashIterations: 10000,
            tokenExpiryHours: 24,
            userDataPath: 'MyAwesomeGame'
        });

        if (success) {
            // Try to auto-login with saved session
            await this.tryAutoLogin();
        } else {
            this.showStatus('Failed to initialize authentication');
        }
    },

    async tryAutoLogin() {
        // Load saved authentication state
        await this.authExtension.loadAuthState();

        if (this.authExtension.isLoggedIn()) {
            const username = this.authExtension.getCurrentUsername();
            this.showStatus(`Welcome back, ${username}!`);
            this.showGamePanel();
        } else {
            this.showLoginPanel();
        }
    },

    showLoginPanel() {
        this.loginPanel.active = true;
        this.gamePanel.active = false;
        this.clearInputs();
    },

    showGamePanel() {
        this.loginPanel.active = false;
        this.gamePanel.active = true;
        // Initialize your game logic here
        this.startGame();
    },

    clearInputs() {
        if (this.usernameInput) this.usernameInput.string = '';
        if (this.passwordInput) this.passwordInput.string = '';
    },

    // UI Event Handlers
    onRegisterButtonClicked() {
        const username = this.usernameInput.string.trim();
        const password = this.passwordInput.string.trim();

        if (!username || !password) {
            this.showStatus('Please enter username and password');
            return;
        }

        this.authExtension.registerUser(username, password, (success, userId, message) => {
            if (success) {
                this.showStatus(`Registration successful! User ID: ${userId}`);
                // Auto-login after successful registration
                this.onLoginButtonClicked();
            } else {
                this.showStatus(`Registration failed: ${message}`);
            }
        });
    },

    onLoginButtonClicked() {
        const username = this.usernameInput.string.trim();
        const password = this.passwordInput.string.trim();

        if (!username || !password) {
            this.showStatus('Please enter username and password');
            return;
        }

        this.authExtension.loginUser(username, password, (success, token, userId, username, message) => {
            if (success) {
                this.showStatus(`Login successful! Welcome ${username}`);
                // Save token for session persistence
                cc.sys.localStorage.setItem('auth_token', token);
                this.showGamePanel();
            } else {
                this.showStatus(`Login failed: ${message}`);
            }
        });
    },

    onLogoutButtonClicked() {
        this.authExtension.logoutUser((success, message) => {
            if (success) {
                this.showStatus('Logged out successfully');
                // Clear saved token
                cc.sys.localStorage.removeItem('auth_token');
                this.showLoginPanel();
            } else {
                this.showStatus(`Logout failed: ${message}`);
            }
        });
    },

    // Game Logic
    startGame() {
        // Your game initialization code here
        console.log('Game started for user:', this.authExtension.getCurrentUsername());

        // Example: Load user progress, initialize game state, etc.
        this.loadUserProgress();
        this.initializeGameWorld();
    },

    loadUserProgress() {
        // Load user-specific game data
        const userId = this.authExtension.getCurrentUserId();
        // Implementation depends on your game's save system
    },

    initializeGameWorld() {
        // Set up your game world
        // This is where your main game logic would go
    },

    // Authentication Event Listeners
    onEnable() {
        // Listen for authentication events
        cc.systemEvent.on('degenhf:register_completed', this.onRegisterCompleted, this);
        cc.systemEvent.on('degenhf:login_completed', this.onLoginCompleted, this);
    },

    onDisable() {
        // Clean up event listeners
        cc.systemEvent.off('degenhf:register_completed', this.onRegisterCompleted, this);
        cc.systemEvent.off('degenhf:login_completed', this.onLoginCompleted, this);
    },

    onRegisterCompleted(success, userId, message) {
        // Handle register event (alternative to callback approach)
        console.log('Register event received:', success, userId, message);
    },

    onLoginCompleted(success, token, userId, username, message) {
        // Handle login event (alternative to callback approach)
        console.log('Login event received:', success, token, userId, username, message);
    },

    showStatus(message) {
        if (this.statusLabel) {
            this.statusLabel.string = message;
        }
        console.log('Status:', message);
    },

    // Lifecycle methods
    onDestroy() {
        // Save authentication state when scene is destroyed
        if (this.authExtension) {
            this.authExtension.saveAuthState();
        }
    }
});

// Example UI Setup (in Cocos Creator Scene):
/*
Scene Hierarchy:
├── Canvas
│   ├── AuthExtension (attach DegenHFAuthExtension component)
│   ├── LoginPanel
│   │   ├── UsernameInput (EditBox)
│   │   ├── PasswordInput (EditBox)
│   │   ├── RegisterButton
│   │   ├── LoginButton
│   │   └── StatusLabel (Label)
│   └── GamePanel
│       ├── GameContent
│       ├── LogoutButton
│       └── PlayerInfo (Label)
└── MainGame (attach this script to Canvas)
*/

// Example GameManager for more complex games
cc.Class({
    extends: cc.Component,

    properties: {
        authExtension: {
            default: null,
            type: require('DegenHFAuthExtension')
        }
    },

    statics: {
        instance: null
    },

    onLoad() {
        GameManager.instance = this;
        this.initializeAuth();
    },

    async initializeAuth() {
        const success = await this.authExtension.init({
            userDataPath: 'MyGameAuth',
            hashIterations: 10000,
            tokenExpiryHours: 24
        });

        if (success) {
            console.log('Authentication system ready');
            this.emit('auth-ready');
        } else {
            console.error('Failed to initialize authentication');
        }
    },

    // Global authentication methods
    async registerPlayer(username, password) {
        return new Promise((resolve) => {
            this.authExtension.registerUser(username, password, (success, userId, message) => {
                resolve({ success, userId, message });
            });
        });
    },

    async loginPlayer(username, password) {
        return new Promise((resolve) => {
            this.authExtension.loginUser(username, password, (success, token, userId, username, message) => {
                resolve({ success, token, userId, username, message });
            });
        });
    },

    logoutPlayer() {
        return new Promise((resolve) => {
            this.authExtension.logoutUser((success, message) => {
                resolve({ success, message });
            });
        });
    },

    isPlayerLoggedIn() {
        return this.authExtension.isLoggedIn();
    },

    getCurrentPlayerId() {
        return this.authExtension.getCurrentUserId();
    },

    getCurrentPlayerName() {
        return this.authExtension.getCurrentUsername();
    },

    // Game-specific authentication integration
    async savePlayerProgress(progressData) {
        if (!this.isPlayerLoggedIn()) {
            return { success: false, message: 'Player not logged in' };
        }

        const userId = this.getCurrentPlayerId();
        // Save progress data associated with userId
        // Implementation depends on your save system

        return { success: true, message: 'Progress saved' };
    },

    async loadPlayerProgress() {
        if (!this.isPlayerLoggedIn()) {
            return { success: false, message: 'Player not logged in' };
        }

        const userId = this.getCurrentPlayerId();
        // Load progress data for userId
        // Implementation depends on your save system

        return { success: true, progressData: {} };
    }
});

// Usage example in other scripts:
/*
// In any other script
const GameManager = require('GameManager');

async function saveGame() {
    if (GameManager.instance.isPlayerLoggedIn()) {
        const result = await GameManager.instance.savePlayerProgress(gameData);
        if (result.success) {
            console.log('Game saved successfully');
        }
    }
}
*/