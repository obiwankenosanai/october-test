const { verifyAccessToken } = require('./jwt');
const { requireRole } = require('./roles');
const rateLimiter = require('./rate-limit');

const BEARER_PREFIX = 'Bearer ';

const defaultRateLimiter = rateLimiter({ windowMs: 60000, max: 100 });

function authenticate(req, res, next) {
  defaultRateLimiter(req, res, function (rateLimitErr) {
    if (rateLimitErr) {
      return next(rateLimitErr);
    }

    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith(BEARER_PREFIX)) {
      return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }

    const token = authHeader.slice(BEARER_PREFIX.length);

    try {
      const payload = verifyAccessToken(token);
      req.user = payload;
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired' });
      }
      return res.status(401).json({ error: 'Invalid token' });
    }
  });
}

function authenticateWithRole(role) {
  const checkRole = requireRole(role);
  return function (req, res, next) {
    authenticate(req, res, function (err) {
      if (err) {
        return next(err);
      }
      checkRole(req, res, next);
    });
  };
}

module.exports = { authenticate, authenticateWithRole };
