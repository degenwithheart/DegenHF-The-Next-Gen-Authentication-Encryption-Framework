/**
 * DegenHF Cocos Creator Authentication Extension
 *
 * Provides easy-to-use authentication integration for Cocos Creator games
 * with automatic scene management and event callbacks.
 */

const DegenHF = DegenHF || {};

(function() {
    'use strict';

    /**
     * Cocos Creator extension for DegenHF ECC authentication
     */
    class AuthExtension extends cc.Component {
        constructor() {
            super();
            this.authHandler = null;
            this.initialized = false;
            this.config = {
                hashIterations: 10000,
                tokenExpiryHours: 24,
                cacheExpiryMinutes: 5,
                userDataPath: 'DegenHFAuth'
            };
        }

        /**
         * Initialize the extension
         * @param {Object} config - Configuration options
         * @returns {Promise<boolean>} Success status
         */
        async init(config = {}) {
            if (this.initialized) {
                return true;
            }

            // Merge config
            Object.assign(this.config, config);

            try {
                // Create auth handler
                this.authHandler = new DegenHF.ECCAuthHandler(this.config);
                this.initialized = await this.authHandler.initialize();

                if (this.initialized) {
                    console.log('DegenHF Cocos Creator Auth Extension initialized successfully');
                }

                return this.initialized;
            } catch (error) {
                console.error('Failed to initialize auth extension:', error);
                return false;
            }
        }

        /**
         * Register a new user
         * @param {string} username - Username for registration
         * @param {string} password - Password for registration
         * @param {Function} callback - Callback function for result
         */
        async registerUser(username, password, callback = null) {
            if (!this.initialized || !this.authHandler) {
                if (callback) callback(false, '', 'Extension not initialized');
                return;
            }

            try {
                const result = await this.authHandler.registerUser(username, password);

                // Emit event
                cc.systemEvent.emit('degenhf:register_completed', result.success, result.userId, result.errorMessage);

                if (callback) {
                    callback(result.success, result.userId, result.errorMessage);
                }
            } catch (error) {
                console.error('Register user error:', error);
                if (callback) callback(false, '', error.message);
            }
        }

        /**
         * Login user
         * @param {string} username - Username for login
         * @param {string} password - Password for login
         * @param {Function} callback - Callback function for result
         */
        async loginUser(username, password, callback = null) {
            if (!this.initialized || !this.authHandler) {
                if (callback) callback(false, '', '', '', 'Extension not initialized');
                return;
            }

            try {
                const result = await this.authHandler.authenticateUser(username, password);

                // Emit event
                cc.systemEvent.emit('degenhf:login_completed', result.success, result.token, result.userId, result.username, result.errorMessage);

                if (callback) {
                    callback(result.success, result.token, result.userId, result.username, result.errorMessage);
                }
            } catch (error) {
                console.error('Login user error:', error);
                if (callback) callback(false, '', '', '', error.message);
            }
        }

        /**
         * Logout current user
         * @param {Function} callback - Callback function for result
         */
        logoutUser(callback = null) {
            if (!this.initialized || !this.authHandler) {
                if (callback) callback(false, 'Extension not initialized');
                return;
            }

            try {
                this.authHandler.logout();
                this.authHandler.saveAuthData();

                if (callback) {
                    callback(true, 'Logged out successfully');
                }
            } catch (error) {
                console.error('Logout error:', error);
                if (callback) callback(false, error.message);
            }
        }

        /**
         * Check if user is logged in
         * @returns {boolean} Login status
         */
        isLoggedIn() {
            if (!this.initialized || !this.authHandler) {
                return false;
            }
            return this.authHandler.isUserLoggedIn();
        }

        /**
         * Get current user ID
         * @returns {string} Current user ID
         */
        getCurrentUserId() {
            if (!this.initialized || !this.authHandler) {
                return '';
            }
            return this.authHandler.getCurrentUserId();
        }

        /**
         * Get current username
         * @returns {string} Current username
         */
        getCurrentUsername() {
            if (!this.initialized || !this.authHandler) {
                return '';
            }
            return this.authHandler.getCurrentUsername();
        }

        /**
         * Verify authentication token
         * @param {string} token - Token to verify
         * @param {Function} callback - Callback function for result
         */
        async verifyToken(token, callback = null) {
            if (!this.initialized || !this.authHandler) {
                if (callback) callback(false, 'Extension not initialized');
                return;
            }

            try {
                const result = await this.authHandler.verifyToken(token);

                // Emit event
                cc.systemEvent.emit('degenhf:verify_completed', result.valid, result.valid ? 'Token valid' : result.errorMessage);

                if (callback) {
                    callback(result.valid, result.valid ? 'Token valid' : result.errorMessage);
                }
            } catch (error) {
                console.error('Verify token error:', error);
                if (callback) callback(false, error.message);
            }
        }

        /**
         * Create a secure session
         * @param {Function} callback - Callback function with session ID
         */
        createSession(callback = null) {
            if (!this.initialized || !this.authHandler) {
                if (callback) callback('');
                return;
            }

            const userId = this.authHandler.getCurrentUserId();
            if (!userId) {
                if (callback) callback('');
                return;
            }

            const sessionId = this.authHandler.createSession(userId);
            if (callback) callback(sessionId);
        }

        /**
         * Get session information
         * @param {string} sessionId - Session ID to query
         * @param {Function} callback - Callback function with user info
         */
        async getSessionInfo(sessionId, callback = null) {
            if (!this.initialized || !this.authHandler) {
                if (callback) callback(false, '', '');
                return;
            }

            try {
                const result = await this.authHandler.getSession(sessionId);
                if (callback) {
                    callback(result.valid, result.userId, result.username);
                }
            } catch (error) {
                console.error('Get session info error:', error);
                if (callback) callback(false, '', '');
            }
        }

        /**
         * Save authentication state
         */
        saveAuthState() {
            if (this.initialized && this.authHandler) {
                this.authHandler.saveAuthData();
            }
        }

        /**
         * Load authentication state
         */
        async loadAuthState() {
            if (this.initialized && this.authHandler) {
                await this.authHandler.loadAuthData();
            }
        }

        /**
         * Get the underlying auth handler
         * @returns {Object} ECC auth handler instance
         */
        getAuthHandler() {
            return this.authHandler;
        }

        /**
         * Called when component is destroyed
         */
        onDestroy() {
            if (this.authHandler) {
                this.authHandler.logout();
                this.saveAuthState();
            }
        }
    }

    // Register component
    cc.Class({
        extends: AuthExtension,
        name: 'DegenHFAuthExtension',

        properties: {
            // Configuration properties that can be set in editor
            hashIterations: {
                default: 10000,
                type: cc.Integer,
                tooltip: 'Number of password hashing iterations'
            },
            tokenExpiryHours: {
                default: 24,
                type: cc.Integer,
                tooltip: 'Token expiry time in hours'
            },
            cacheExpiryMinutes: {
                default: 5,
                type: cc.Integer,
                tooltip: 'Cache expiry time in minutes'
            },
            userDataPath: {
                default: 'DegenHFAuth',
                type: cc.String,
                tooltip: 'Path for storing user authentication data'
            }
        },

        onLoad() {
            // Initialize with component properties
            const config = {
                hashIterations: this.hashIterations,
                tokenExpiryHours: this.tokenExpiryHours,
                cacheExpiryMinutes: this.cacheExpiryMinutes,
                userDataPath: this.userDataPath
            };

            this.init(config);
        }
    });

    // Export to global namespace
    DegenHF.AuthExtension = AuthExtension;

})();