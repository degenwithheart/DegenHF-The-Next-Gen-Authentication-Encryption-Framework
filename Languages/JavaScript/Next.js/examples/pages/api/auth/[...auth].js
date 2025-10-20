/**
 * Next.js Integration Example for DegenHF ECC Authentication
 *
 * This example shows how to integrate the ECC authentication package with Next.js.
 */

// pages/api/auth/[...auth].js
const { EccAuthHandler } = require('degenhf-nextjs-ecc-auth');

const authConfig = {
  hashIterations: 100000,
  tokenExpiry: 3600,    // 1 hour
  cacheSize: 10000,
  cacheTTL: 300         // 5 minutes
};

const authHandler = new EccAuthHandler(authConfig);

export default authHandler.createApiHandler();

// Alternative manual implementation:
/*
export default async function handler(req, res) {
  const { auth } = req.query;
  const action = auth[0];

  switch (action) {
    case 'register':
      if (req.method === 'POST') {
        try {
          const { username, password } = req.body;
          const userId = await authHandler.register(username, password);
          res.status(200).json({ userId, status: 'success' });
        } catch (error) {
          res.status(400).json({ error: error.message });
        }
      }
      break;

    case 'login':
      if (req.method === 'POST') {
        try {
          const { username, password } = req.body;
          const token = await authHandler.authenticate(username, password);
          res.status(200).json({ token, status: 'success' });
        } catch (error) {
          res.status(401).json({ error: error.message });
        }
      }
      break;

    case 'verify':
      if (req.method === 'GET') {
        try {
          const authHeader = req.headers.authorization;
          if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authorization header required' });
          }

          const token = authHeader.substring(7);
          const userData = authHandler.verifyToken(token);

          res.status(200).json({
            status: 'success',
            user: {
              id: userData.id,
              username: userData.username
            }
          });
        } catch (error) {
          res.status(401).json({ error: error.message });
        }
      }
      break;

    default:
      res.status(404).json({ error: 'Action not found' });
  }
}
*/