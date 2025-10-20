/**
 * DegenHF Authentication Demo Scene
 *
 * Demonstrates how to integrate ECC authentication into Cocos Creator games
 */

const DegenHF = DegenHF || {};

(function() {
    'use strict';

    cc.Class({
        extends: cc.Component,

        properties: {
            // UI References
            statusLabel: cc.Label,
            usernameField: cc.EditBox,
            passwordField: cc.EditBox,
            loginButton: cc.Button,
            registerButton: cc.Button,
            logoutButton: cc.Button,
            verifyButton: cc.Button,

            // Auth extension reference
            authExtension: {
                default: null,
                type: DegenHF.AuthExtension
            }
        },

        onLoad() {
            // Get or create auth extension
            if (!this.authExtension) {
                this.authExtension = this.getComponent('DegenHFAuthExtension');
                if (!this.authExtension) {
                    // Create auth extension component
                    this.authExtension = this.addComponent('DegenHFAuthExtension');
                }
            }

            // Setup UI event listeners
            this.loginButton.node.on('click', this.onLoginPressed, this);
            this.registerButton.node.on('click', this.onRegisterPressed, this);
            this.logoutButton.node.on('click', this.onLogoutPressed, this);
            this.verifyButton.node.on('click', this.onVerifyPressed, this);

            // Setup auth event listeners
            cc.systemEvent.on('degenhf:register_completed', this.onRegisterCompleted, this);
            cc.systemEvent.on('degenhf:login_completed', this.onLoginCompleted, this);
            cc.systemEvent.on('degenhf:verify_completed', this.onVerifyCompleted, this);

            this.initializeAuth();
        },

        onDestroy() {
            // Cleanup event listeners
            cc.systemEvent.off('degenhf:register_completed', this.onRegisterCompleted, this);
            cc.systemEvent.off('degenhf:login_completed', this.onLoginCompleted, this);
            cc.systemEvent.off('degenhf:verify_completed', this.onVerifyCompleted, this);
        },

        async initializeAuth() {
            this.showMessage('Initializing authentication system...');

            const config = {
                hashIterations: 10000,
                tokenExpiryHours: 24,
                userDataPath: 'DegenHFDemo'
            };

            const success = await this.authExtension.init(config);
            if (success) {
                this.showMessage('Authentication system initialized');
                this.updateUI();
            } else {
                this.showMessage('Failed to initialize authentication system');
            }
        },

        onLoginPressed() {
            const username = this.usernameField.string.trim();
            const password = this.passwordField.string.trim();

            if (!username || !password) {
                this.showMessage('Please enter username and password');
                return;
            }

            this.showMessage('Logging in...');
            this.disableButtons();

            this.authExtension.loginUser(username, password, (success, token, userId, username, message) => {
                this.enableButtons();
                if (success) {
                    this.clearFields();
                    this.updateUI();
                    this.showMessage(`Login successful! Welcome ${username}`);
                } else {
                    this.showMessage(`Login failed: ${message}`);
                }
            });
        },

        onRegisterPressed() {
            const username = this.usernameField.string.trim();
            const password = this.passwordField.string.trim();

            if (!username || !password) {
                this.showMessage('Please enter username and password');
                return;
            }

            if (password.length < 6) {
                this.showMessage('Password must be at least 6 characters');
                return;
            }

            this.showMessage('Registering...');
            this.disableButtons();

            this.authExtension.registerUser(username, password, (success, userId, message) => {
                this.enableButtons();
                if (success) {
                    this.clearFields();
                    this.showMessage('Registration successful! You can now login.');
                } else {
                    this.showMessage(`Registration failed: ${message}`);
                }
            });
        },

        onLogoutPressed() {
            this.authExtension.logoutUser((success, message) => {
                this.updateUI();
                if (success) {
                    this.showMessage('Logged out successfully');
                } else {
                    this.showMessage(`Logout failed: ${message}`);
                }
            });
        },

        onVerifyPressed() {
            // For demo purposes, create a session and verify it
            this.authExtension.createSession((sessionId) => {
                if (!sessionId) {
                    this.showMessage('Failed to create session');
                    return;
                }

                this.authExtension.getSessionInfo(sessionId, (valid, userId, username) => {
                    if (valid) {
                        this.showMessage(`Session valid for user: ${username}`);
                    } else {
                        this.showMessage('Session invalid');
                    }
                });
            });
        },

        onRegisterCompleted(success, userId, message) {
            // Handle register event (alternative to callback)
            console.log('Register event:', success, userId, message);
        },

        onLoginCompleted(success, token, userId, username, message) {
            // Handle login event (alternative to callback)
            console.log('Login event:', success, token, userId, username, message);
        },

        onVerifyCompleted(valid, message) {
            // Handle verify event (alternative to callback)
            console.log('Verify event:', valid, message);
        },

        updateUI() {
            const loggedIn = this.authExtension.isLoggedIn();

            if (loggedIn) {
                const username = this.authExtension.getCurrentUsername();
                const userId = this.authExtension.getCurrentUserId();
                this.statusLabel.string = `Logged in as: ${username}\nID: ${userId.substr(0, 8)}...`;

                this.loginButton.node.active = false;
                this.registerButton.node.active = false;
                this.logoutButton.node.active = true;
                this.verifyButton.node.active = true;
            } else {
                this.statusLabel.string = 'Not logged in';

                this.loginButton.node.active = true;
                this.registerButton.node.active = true;
                this.logoutButton.node.active = false;
                this.verifyButton.node.active = false;
            }
        },

        showMessage(message) {
            this.statusLabel.string = message;
            console.log('Auth Demo:', message);
        },

        clearFields() {
            this.usernameField.string = '';
            this.passwordField.string = '';
        },

        disableButtons() {
            this.loginButton.interactable = false;
            this.registerButton.interactable = false;
            this.logoutButton.interactable = false;
            this.verifyButton.interactable = false;
        },

        enableButtons() {
            this.loginButton.interactable = true;
            this.registerButton.interactable = true;
            this.logoutButton.interactable = true;
            this.verifyButton.interactable = true;
        }
    });

})();