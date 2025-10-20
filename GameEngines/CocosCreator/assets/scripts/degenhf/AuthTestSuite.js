// Test suite for Cocos Creator ECC Authentication
// Run this script in Cocos Creator to validate the authentication system

const { DegenHF } = require('DegenHF');

cc.Class({
    extends: cc.Component,

    properties: {
        testResults: {
            default: null,
            type: cc.Label
        },
        runTestsButton: {
            default: null,
            type: cc.Button
        }
    },

    onLoad() {
        if (this.runTestsButton) {
            this.runTestsButton.node.on('click', this.runAllTests, this);
        }
    },

    async runAllTests() {
        console.log('=== Starting Cocos Creator ECC Authentication Tests ===');

        const results = {
            total: 0,
            passed: 0,
            failed: 0,
            tests: []
        };

        // Test 1: Initialization
        await this.testInitialization(results);

        // Test 2: User Registration
        await this.testUserRegistration(results);

        // Test 3: User Authentication
        await this.testUserAuthentication(results);

        // Test 4: Token Verification
        await this.testTokenVerification(results);

        // Test 5: Session Management
        await this.testSessionManagement(results);

        // Test 6: Logout Functionality
        await this.testLogoutFunctionality(results);

        // Test 7: Data Persistence
        await this.testDataPersistence(results);

        // Test 8: Error Handling
        await this.testErrorHandling(results);

        // Test 9: Component Integration
        await this.testComponentIntegration(results);

        // Test 10: Event System
        await this.testEventSystem(results);

        this.displayResults(results);
        console.log('=== Test Suite Complete ===');
        console.log(`Results: ${results.passed}/${results.total} tests passed`);
    },

    async testInitialization(results) {
        console.log('Testing initialization...');

        const authHandler = new DegenHF.ECCAuthHandler({
            hashIterations: 1000, // Faster for testing
            tokenExpiryHours: 1,
            userDataPath: 'TestAuth'
        });

        const success = await authHandler.initialize();

        this.recordTest(results, 'Initialization', success, 'Auth handler should initialize successfully');
    },

    async testUserRegistration(results) {
        console.log('Testing user registration...');

        const authHandler = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestAuth'
        });

        await authHandler.initialize();

        // Test successful registration
        const result1 = await authHandler.registerUser('testuser1', 'password123');
        this.recordTest(results, 'User Registration - Success', result1.success, 'Should register new user successfully');

        // Test duplicate registration
        const result2 = await authHandler.registerUser('testuser1', 'password456');
        this.recordTest(results, 'User Registration - Duplicate', !result2.success, 'Should reject duplicate username');

        // Test invalid username
        const result3 = await authHandler.registerUser('', 'password123');
        this.recordTest(results, 'User Registration - Empty Username', !result3.success, 'Should reject empty username');

        // Test invalid password
        const result4 = await authHandler.registerUser('testuser2', '');
        this.recordTest(results, 'User Registration - Empty Password', !result4.success, 'Should reject empty password');
    },

    async testUserAuthentication(results) {
        console.log('Testing user authentication...');

        const authHandler = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestAuth'
        });

        await authHandler.initialize();

        // Register a user first
        await authHandler.registerUser('testuser3', 'password123');

        // Test successful login
        const result1 = await authHandler.authenticateUser('testuser3', 'password123');
        this.recordTest(results, 'User Authentication - Success', result1.success, 'Should authenticate valid credentials');

        // Test wrong password
        const result2 = await authHandler.authenticateUser('testuser3', 'wrongpassword');
        this.recordTest(results, 'User Authentication - Wrong Password', !result2.success, 'Should reject wrong password');

        // Test non-existent user
        const result3 = await authHandler.authenticateUser('nonexistent', 'password123');
        this.recordTest(results, 'User Authentication - Non-existent User', !result3.success, 'Should reject non-existent user');
    },

    async testTokenVerification(results) {
        console.log('Testing token verification...');

        const authHandler = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestAuth'
        });

        await authHandler.initialize();

        // Register and login to get a token
        await authHandler.registerUser('testuser4', 'password123');
        const loginResult = await authHandler.authenticateUser('testuser4', 'password123');

        if (loginResult.success) {
            // Test valid token
            const verifyResult1 = await authHandler.verifyToken(loginResult.token);
            this.recordTest(results, 'Token Verification - Valid', verifyResult1.valid, 'Should verify valid token');

            // Test invalid token
            const verifyResult2 = await authHandler.verifyToken('invalid.token.here');
            this.recordTest(results, 'Token Verification - Invalid', !verifyResult2.valid, 'Should reject invalid token');

            // Test expired token (simulate by creating handler with very short expiry)
            const shortExpiryHandler = new DegenHF.ECCAuthHandler({
                hashIterations: 1000,
                tokenExpiryHours: 0.0001, // Very short expiry
                userDataPath: 'TestAuth'
            });
            await shortExpiryHandler.initialize();
            await shortExpiryHandler.registerUser('testuser5', 'password123');
            const shortLogin = await shortExpiryHandler.authenticateUser('testuser5', 'password123');

            if (shortLogin.success) {
                // Wait a bit for token to expire
                await this.delay(100);
                const expiredVerify = await shortExpiryHandler.verifyToken(shortLogin.token);
                this.recordTest(results, 'Token Verification - Expired', !expiredVerify.valid, 'Should reject expired token');
            }
        } else {
            this.recordTest(results, 'Token Verification - Setup Failed', false, 'Failed to set up token verification test');
        }
    },

    async testSessionManagement(results) {
        console.log('Testing session management...');

        const authHandler = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestAuth'
        });

        await authHandler.initialize();

        // Register and login
        await authHandler.registerUser('testuser6', 'password123');
        const loginResult = await authHandler.authenticateUser('testuser6', 'password123');

        if (loginResult.success) {
            // Create session
            const sessionId = authHandler.createSession(loginResult.userId);
            this.recordTest(results, 'Session Creation', sessionId !== null && sessionId !== '', 'Should create session successfully');

            // Get session info
            const sessionInfo = await authHandler.getSession(sessionId);
            this.recordTest(results, 'Session Retrieval', sessionInfo.valid && sessionInfo.userId === loginResult.userId, 'Should retrieve valid session info');

            // Test invalid session
            const invalidSession = await authHandler.getSession('invalid-session-id');
            this.recordTest(results, 'Session Retrieval - Invalid', !invalidSession.valid, 'Should reject invalid session');
        } else {
            this.recordTest(results, 'Session Management - Setup Failed', false, 'Failed to set up session test');
        }
    },

    async testLogoutFunctionality(results) {
        console.log('Testing logout functionality...');

        const authHandler = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestAuth'
        });

        await authHandler.initialize();

        // Register and login
        await authHandler.registerUser('testuser7', 'password123');
        const loginResult = await authHandler.authenticateUser('testuser7', 'password123');

        if (loginResult.success) {
            // Verify logged in
            this.recordTest(results, 'Logout - Initially Logged In', authHandler.isUserLoggedIn(), 'User should be logged in initially');

            // Logout
            authHandler.logout();

            // Verify logged out
            this.recordTest(results, 'Logout - Successfully Logged Out', !authHandler.isUserLoggedIn(), 'User should be logged out after logout()');

            // Verify methods return null/empty after logout
            this.recordTest(results, 'Logout - User ID Cleared', authHandler.getCurrentUserId() === null, 'Current user ID should be cleared');
            this.recordTest(results, 'Logout - Username Cleared', authHandler.getCurrentUsername() === null, 'Current username should be cleared');
        } else {
            this.recordTest(results, 'Logout Functionality - Setup Failed', false, 'Failed to set up logout test');
        }
    },

    async testDataPersistence(results) {
        console.log('Testing data persistence...');

        const authHandler1 = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestPersistence'
        });

        await authHandler1.initialize();

        // Register user
        const regResult = await authHandler1.registerUser('persistuser', 'password123');
        this.recordTest(results, 'Data Persistence - Registration', regResult.success, 'Should register user for persistence test');

        // Save data
        await authHandler1.saveAuthData();

        // Create new handler instance
        const authHandler2 = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestPersistence'
        });

        await authHandler2.initialize();

        // Load data
        await authHandler2.loadAuthData();

        // Try to authenticate with loaded data
        const authResult = await authHandler2.authenticateUser('persistuser', 'password123');
        this.recordTest(results, 'Data Persistence - Authentication', authResult.success, 'Should authenticate user with persisted data');
    },

    async testErrorHandling(results) {
        console.log('Testing error handling...');

        const authHandler = new DegenHF.ECCAuthHandler({
            hashIterations: 1000,
            tokenExpiryHours: 1,
            userDataPath: 'TestAuth'
        });

        // Test operations without initialization
        try {
            await authHandler.registerUser('test', 'test');
            this.recordTest(results, 'Error Handling - Uninitialized Register', false, 'Should throw error when registering without initialization');
        } catch (error) {
            this.recordTest(results, 'Error Handling - Uninitialized Register', true, 'Should throw error when registering without initialization');
        }

        // Initialize and test invalid inputs
        await authHandler.initialize();

        const result1 = await authHandler.registerUser(null, 'password');
        this.recordTest(results, 'Error Handling - Null Username', !result1.success, 'Should handle null username');

        const result2 = await authHandler.registerUser('user', null);
        this.recordTest(results, 'Error Handling - Null Password', !result2.success, 'Should handle null password');

        const result3 = await authHandler.authenticateUser(null, 'password');
        this.recordTest(results, 'Error Handling - Null Auth Username', !result3.success, 'Should handle null auth username');

        const result4 = await authHandler.authenticateUser('user', null);
        this.recordTest(results, 'Error Handling - Null Auth Password', !result4.success, 'Should handle null auth password');
    },

    async testComponentIntegration(results) {
        console.log('Testing component integration...');

        // Create a node with the auth extension
        const testNode = new cc.Node('TestAuthNode');
        const authExtension = testNode.addComponent('DegenHFAuthExtension');

        if (authExtension) {
            // Initialize component
            const initSuccess = await authExtension.init({
                hashIterations: 1000,
                tokenExpiryHours: 1,
                userDataPath: 'TestComponent'
            });

            this.recordTest(results, 'Component Integration - Initialization', initSuccess, 'Component should initialize successfully');

            // Test component methods exist
            this.recordTest(results, 'Component Integration - Methods Exist',
                typeof authExtension.registerUser === 'function' &&
                typeof authExtension.loginUser === 'function' &&
                typeof authExtension.logoutUser === 'function' &&
                typeof authExtension.isLoggedIn === 'function',
                'Component should have required methods');

            // Clean up
            testNode.destroy();
        } else {
            this.recordTest(results, 'Component Integration - Component Creation', false, 'Failed to create auth extension component');
        }
    },

    async testEventSystem(results) {
        console.log('Testing event system...');

        let eventFired = false;
        let eventData = null;

        // Listen for register event
        const eventListener = (success, userId, message) => {
            eventFired = true;
            eventData = { success, userId, message };
        };

        cc.systemEvent.on('degenhf:register_completed', eventListener);

        // Create component and register user
        const testNode = new cc.Node('TestEventNode');
        const authExtension = testNode.addComponent('DegenHFAuthExtension');

        if (authExtension) {
            await authExtension.init({
                hashIterations: 1000,
                tokenExpiryHours: 1,
                userDataPath: 'TestEvent'
            });

            // Register user (should fire event)
            authExtension.registerUser('eventuser', 'password123', () => {});

            // Wait a bit for async operation
            await this.delay(100);

            this.recordTest(results, 'Event System - Register Event', eventFired, 'Register event should fire');

            if (eventFired) {
                this.recordTest(results, 'Event System - Event Data', eventData.success === true, 'Event should contain success data');
            }

            // Clean up
            cc.systemEvent.off('degenhf:register_completed', eventListener);
            testNode.destroy();
        } else {
            this.recordTest(results, 'Event System - Setup', false, 'Failed to set up event test');
        }
    },

    recordTest(results, name, passed, description) {
        results.total++;
        if (passed) {
            results.passed++;
            console.log(`✓ PASS: ${name}`);
        } else {
            results.failed++;
            console.log(`✗ FAIL: ${name} - ${description}`);
        }

        results.tests.push({
            name,
            passed,
            description
        });
    },

    displayResults(results) {
        const summary = `Test Results: ${results.passed}/${results.total} passed (${results.failed} failed)`;

        if (this.testResults) {
            this.testResults.string = summary;
        }

        console.log(summary);

        // Log detailed results
        results.tests.forEach(test => {
            const status = test.passed ? 'PASS' : 'FAIL';
            console.log(`${status}: ${test.name}`);
            if (!test.passed) {
                console.log(`  Description: ${test.description}`);
            }
        });
    },

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
});