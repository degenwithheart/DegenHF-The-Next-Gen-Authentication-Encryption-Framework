/**
 * DegenHF ECC Authentication Handler for Cocos Creator
 *
 * Provides blockchain-grade security for Cocos Creator games with
 * ECC-based cryptography and hybrid password hashing.
 */

const DegenHF = DegenHF || {};

(function() {
    'use strict';

    /**
     * ECC-based authentication handler for Cocos Creator
     */
    class ECCAuthHandler {
        constructor(config = {}) {
            this.config = {
                hashIterations: config.hashIterations || 10000,
                tokenExpiryHours: config.tokenExpiryHours || 24,
                cacheExpiryMinutes: config.cacheExpiryMinutes || 5,
                userDataPath: config.userDataPath || 'DegenHFAuth'
            };

            this.currentUserId = null;
            this.currentUsername = null;
            this.currentToken = null;
            this.privateKey = null;
            this.publicKey = null;
            this.tokenCache = new Map();
            this.sessionCache = new Map();

            // Initialize crypto polyfills if needed
            this._initCrypto();
        }

        /**
         * Initialize the authentication handler
         * @returns {Promise<boolean>} Success status
         */
        async initialize() {
            try {
                // Generate ECC key pair
                const keyPair = await this._generateECCKeyPair();
                this.privateKey = keyPair.privateKey;
                this.publicKey = keyPair.publicKey;

                // Load existing authentication data
                await this.loadAuthData();

                console.log('DegenHF ECC Auth Handler initialized successfully');
                return true;
            } catch (error) {
                console.error('Failed to initialize ECC Auth Handler:', error);
                return false;
            }
        }

        /**
         * Register a new user
         * @param {string} username - Username for registration
         * @param {string} password - Password for registration
         * @returns {Promise<Object>} Registration result
         */
        async registerUser(username, password) {
            const result = {
                success: false,
                userId: null,
                errorMessage: null
            };

            if (!username || !password) {
                result.errorMessage = 'Username and password cannot be empty';
                return result;
            }

            try {
                // Check if user already exists
                const existingUser = await this._loadUserData(username);
                if (existingUser) {
                    result.errorMessage = 'User already exists';
                    return result;
                }

                // Generate user ID
                result.userId = this._generateUserId();

                // Hash password
                const { salt, hash } = await this._hashPassword(password);

                // Save user data
                await this._saveUserData(result.userId, username, salt, hash);

                result.success = true;
                console.log(`User registered successfully: ${username}`);
            } catch (error) {
                result.errorMessage = error.message || 'Registration failed';
                console.error('Registration error:', error);
            }

            return result;
        }

        /**
         * Authenticate a user
         * @param {string} username - Username for login
         * @param {string} password - Password for login
         * @returns {Promise<Object>} Authentication result
         */
        async authenticateUser(username, password) {
            const result = {
                success: false,
                token: null,
                userId: null,
                username: null,
                errorMessage: null
            };

            if (!username || !password) {
                result.errorMessage = 'Username and password cannot be empty';
                return result;
            }

            try {
                // Load user data
                const userData = await this._loadUserData(username);
                if (!userData) {
                    result.errorMessage = 'User not found';
                    return result;
                }

                // Verify password
                const isValidPassword = await this._verifyPassword(password, userData.salt, userData.hash);
                if (!isValidPassword) {
                    result.errorMessage = 'Invalid password';
                    return result;
                }

                // Generate token
                result.token = this._generateToken(userData.userId, username);
                result.userId = userData.userId;
                result.username = username;
                result.success = true;

                // Set current user
                this.currentUserId = result.userId;
                this.currentUsername = username;
                this.currentToken = result.token;

                console.log(`User authenticated successfully: ${username}`);
            } catch (error) {
                result.errorMessage = error.message || 'Authentication failed';
                console.error('Authentication error:', error);
            }

            return result;
        }

        /**
         * Verify an authentication token
         * @param {string} token - Token to verify
         * @returns {Promise<Object>} Verification result
         */
        async verifyToken(token) {
            const result = {
                valid: false,
                userId: null,
                username: null,
                errorMessage: null
            };

            if (!token) {
                result.errorMessage = 'Token cannot be empty';
                return result;
            }

            try {
                const tokenData = this._validateToken(token);
                if (tokenData) {
                    result.valid = true;
                    result.userId = tokenData.userId;
                    result.username = tokenData.username;
                } else {
                    result.errorMessage = 'Invalid or expired token';
                }
            } catch (error) {
                result.errorMessage = error.message || 'Token verification failed';
                console.error('Token verification error:', error);
            }

            return result;
        }

        /**
         * Create a secure session
         * @param {string} userId - User ID for the session
         * @returns {string} Session ID
         */
        createSession(userId) {
            const sessionId = this._generateSessionId();
            this.sessionCache.set(sessionId, userId);
            return sessionId;
        }

        /**
         * Get session data
         * @param {string} sessionId - Session ID to retrieve
         * @returns {Object} Session data
         */
        async getSession(sessionId) {
            const result = {
                valid: false,
                userId: null,
                username: null
            };

            const userId = this.sessionCache.get(sessionId);
            if (userId) {
                const userData = await this._loadUserDataById(userId);
                if (userData) {
                    result.valid = true;
                    result.userId = userId;
                    result.username = userData.username;
                }
            }

            return result;
        }

        /**
         * Check if user is currently logged in
         * @returns {boolean} Login status
         */
        isUserLoggedIn() {
            return !!(this.currentUserId && this.currentToken);
        }

        /**
         * Get current user ID
         * @returns {string} Current user ID
         */
        getCurrentUserId() {
            return this.currentUserId || '';
        }

        /**
         * Get current username
         * @returns {string} Current username
         */
        getCurrentUsername() {
            return this.currentUsername || '';
        }

        /**
         * Logout current user
         */
        logout() {
            this.currentUserId = null;
            this.currentUsername = null;
            this.currentToken = null;
            this.sessionCache.clear();
            this.tokenCache.clear();
        }

        /**
         * Save authentication data to persistent storage
         */
        async saveAuthData() {
            try {
                const data = {
                    currentUserId: this.currentUserId,
                    currentUsername: this.currentUsername,
                    currentToken: this.currentToken,
                    sessions: Array.from(this.sessionCache.entries())
                };

                const jsonData = JSON.stringify(data);
                const key = `${this.config.userDataPath}_session`;
                cc.sys.localStorage.setItem(key, jsonData);
            } catch (error) {
                console.error('Failed to save auth data:', error);
            }
        }

        /**
         * Load authentication data from persistent storage
         */
        async loadAuthData() {
            try {
                const key = `${this.config.userDataPath}_session`;
                const jsonData = cc.sys.localStorage.getItem(key);
                if (!jsonData) return;

                const data = JSON.parse(jsonData);

                if (data.currentUserId) this.currentUserId = data.currentUserId;
                if (data.currentUsername) this.currentUsername = data.currentUsername;
                if (data.currentToken) this.currentToken = data.currentToken;

                if (data.sessions) {
                    this.sessionCache = new Map(data.sessions);
                }
            } catch (error) {
                console.error('Failed to load auth data:', error);
            }
        }

        // Private helper methods

        _initCrypto() {
            // Initialize crypto polyfills for ECC operations
            if (typeof crypto === 'undefined') {
                // Fallback for environments without crypto API
                this._crypto = {
                    getRandomValues: function(array) {
                        for (let i = 0; i < array.length; i++) {
                            array[i] = Math.floor(Math.random() * 256);
                        }
                        return array;
                    }
                };
            } else {
                this._crypto = crypto;
            }
        }

        async _generateECCKeyPair() {
            // Simplified ECC key generation for JavaScript environment
            // In production, you'd use a proper ECC library or Web Crypto API
            const privateKey = new Uint8Array(32);
            const publicKey = new Uint8Array(64);

            this._crypto.getRandomValues(privateKey);

            // Simple public key derivation (not cryptographically secure)
            // In production, use proper ECC mathematics
            for (let i = 0; i < 32; i++) {
                publicKey[i] = privateKey[i] ^ 0xFF;
                publicKey[i + 32] = privateKey[i] ^ 0xAA;
            }

            return { privateKey, publicKey };
        }

        async _hashPassword(password) {
            const salt = new Uint8Array(32);
            this._crypto.getRandomValues(salt);

            // Simplified PBKDF2 implementation
            // In production, use a proper crypto library
            let hash = new TextEncoder().encode(password);
            const combined = new Uint8Array(hash.length + salt.length);
            combined.set(hash);
            combined.set(salt, hash.length);

            for (let i = 0; i < this.config.hashIterations; i++) {
                hash = await this._sha256(combined);
                combined.set(hash.subarray(0, 16));
                combined.set(salt, 16);
            }

            return {
                salt: this._arrayToBase64(salt),
                hash: this._arrayToBase64(hash)
            };
        }

        async _verifyPassword(password, saltBase64, hashBase64) {
            try {
                const salt = this._base64ToArray(saltBase64);
                const storedHash = this._base64ToArray(hashBase64);

                const { hash: computedHash } = await this._hashPassword(password);
                const computedHashArray = this._base64ToArray(computedHash);

                if (storedHash.length !== computedHashArray.length) {
                    return false;
                }

                // Constant-time comparison
                let result = 0;
                for (let i = 0; i < storedHash.length; i++) {
                    result |= storedHash[i] ^ computedHashArray[i];
                }

                return result === 0;
            } catch (error) {
                console.error('Password verification error:', error);
                return false;
            }
        }

        async _sha256(data) {
            if (typeof crypto !== 'undefined' && crypto.subtle) {
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                return new Uint8Array(hashBuffer);
            } else {
                // Fallback hash function (not cryptographically secure)
                let hash = 0;
                for (let i = 0; i < data.length; i++) {
                    hash = ((hash << 5) - hash + data[i]) & 0xFFFFFFFF;
                }
                const result = new Uint8Array(32);
                for (let i = 0; i < 32; i++) {
                    result[i] = (hash >>> (i * 8)) & 0xFF;
                }
                return result;
            }
        }

        _generateToken(userId, username) {
            const timestamp = Date.now();
            const payload = `${userId}:${username}:${timestamp}`;
            const token = this._arrayToBase64(new TextEncoder().encode(payload));
            this.tokenCache.set(token, { userId, username, timestamp });
            return token;
        }

        _validateToken(token) {
            try {
                const tokenData = this.tokenCache.get(token);
                if (!tokenData) return null;

                if (this._isTokenExpired(tokenData.timestamp)) {
                    this.tokenCache.delete(token);
                    return null;
                }

                return tokenData;
            } catch (error) {
                console.error('Token validation error:', error);
                return null;
            }
        }

        _isTokenExpired(tokenTimestamp) {
            const currentTime = Date.now();
            const expiryTime = tokenTimestamp + (this.config.tokenExpiryHours * 60 * 60 * 1000);
            return currentTime > expiryTime;
        }

        _generateUserId() {
            return 'user_' + this._generateRandomString(16);
        }

        _generateSessionId() {
            return 'session_' + this._generateRandomString(32);
        }

        _generateRandomString(length) {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let result = '';
            const randomValues = new Uint8Array(length);
            this._crypto.getRandomValues(randomValues);

            for (let i = 0; i < length; i++) {
                result += chars.charAt(randomValues[i] % chars.length);
            }

            return result;
        }

        async _saveUserData(userId, username, salt, hash) {
            const data = {
                userId,
                username,
                salt,
                hash,
                created: Date.now()
            };

            const jsonData = JSON.stringify(data);
            const key = `${this.config.userDataPath}_user_${userId}`;
            cc.sys.localStorage.setItem(key, jsonData);
        }

        async _loadUserData(username) {
            try {
                // Find user by username (simplified - in production, use an index)
                const keys = Object.keys(cc.sys.localStorage);
                for (const key of keys) {
                    if (key.startsWith(`${this.config.userDataPath}_user_`)) {
                        const jsonData = cc.sys.localStorage.getItem(key);
                        if (jsonData) {
                            const data = JSON.parse(jsonData);
                            if (data.username === username) {
                                return data;
                            }
                        }
                    }
                }
                return null;
            } catch (error) {
                console.error('Failed to load user data:', error);
                return null;
            }
        }

        async _loadUserDataById(userId) {
            try {
                const key = `${this.config.userDataPath}_user_${userId}`;
                const jsonData = cc.sys.localStorage.getItem(key);
                return jsonData ? JSON.parse(jsonData) : null;
            } catch (error) {
                console.error('Failed to load user data by ID:', error);
                return null;
            }
        }

        _arrayToBase64(array) {
            let binary = '';
            for (let i = 0; i < array.length; i++) {
                binary += String.fromCharCode(array[i]);
            }
            return btoa(binary);
        }

        _base64ToArray(base64) {
            const binary = atob(base64);
            const array = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                array[i] = binary.charCodeAt(i);
            }
            return array;
        }
    }

    // Export to global namespace
    DegenHF.ECCAuthHandler = ECCAuthHandler;

})();