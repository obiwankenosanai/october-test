const { verifyAccessToken } = require('./tokenService');

const UNAUTHORIZED = 401;

async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(UNAUTHORIZED).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.slice(7);

  if (!token) {
    return res.status(UNAUTHORIZED).json({ error: 'Missing token' });
  }

  try {
    const user = await verifyAccessToken(token);
    req.user = user;
    return next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(UNAUTHORIZED).json({ error: 'Token expired' });
    }
    return res.status(UNAUTHORIZED).json({ error: 'Invalid token' });
  }
}

module.exports = { authenticate };
