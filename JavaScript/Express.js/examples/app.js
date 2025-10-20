/**
 * Express.js Integration Example for DegenHF ECC Authentication
 *
 * This example shows how to integrate the ECC authentication package with Express.js.
 */

const express = require('express');
const { EccAuthHandler } = require('./index');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Configure ECC authentication
const authConfig = {
  hashIterations: 100000,
  tokenExpiry: 3600,    // 1 hour
  cacheSize: 10000,
  cacheTTL: 300         // 5 minutes
};

const authHandler = new EccAuthHandler(authConfig);

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'DegenHF Express ECC Auth API' });
});

// User registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const userId = await authHandler.register(username, password);

    res.json({
      status: 'success',
      userId,
      message: 'User registered successfully'
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ error: error.message });
  }
});

// User login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const token = await authHandler.authenticate(username, password);

    res.json({
      status: 'success',
      token,
      message: 'Login successful'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: error.message });
  }
});

// Protected profile route
app.get('/api/auth/profile', authHandler.jwtAuth(), (req, res) => {
  res.json({
    status: 'success',
    user: {
      id: req.user.id,
      username: req.user.username,
      createdAt: req.user.createdAt
    },
    message: 'Profile accessed successfully'
  });
});

// Create session
app.post('/api/auth/session', authHandler.jwtAuth(), async (req, res) => {
  try {
    const session = await authHandler.createSession(req.user.id);

    res.json({
      status: 'success',
      session: {
        sessionId: session.sessionId,
        expiresAt: session.expiresAt
      }
    });

  } catch (error) {
    console.error('Session creation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get session info
app.get('/api/auth/session/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = authHandler.getSession(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Session not found or expired' });
    }

    res.json({
      status: 'success',
      session: {
        sessionId: session.sessionId,
        userId: session.userId,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt
      }
    });

  } catch (error) {
    console.error('Session retrieval error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`DegenHF Express ECC Auth API listening on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`API docs: http://localhost:${PORT}/api/auth`);
  });
}

module.exports = app;