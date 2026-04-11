const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { validateCredentials } = require('./userService');
const tokenStore = require('./tokenStore');
const { rateLimiter } = require('./rateLimiter');

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'access-secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'refresh-secret';
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
const MAX_LOGIN_ATTEMPTS = 3;

function generateAccessToken(payload) {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
}

router.post('/login', rateLimiter({ max: MAX_LOGIN_ATTEMPTS, windowMs: 15 * 60 * 1000, keyPrefix: 'login' }), async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  let user;
  try {
    user = await validateCredentials(username, password);
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error.' });
  }

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const payload = { sub: user.id, username: user.username, roles: user.roles };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken({ sub: user.id });

  try {
    await tokenStore.saveRefreshToken(user.id, refreshToken);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to persist session.' });
  }

  return res.status(200).json({ accessToken, refreshToken });
});

router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required.' });
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Refresh token has expired.' });
    }
    return res.status(401).json({ error: 'Invalid refresh token.' });
  }

  let isValid;
  try {
    isValid = await tokenStore.validateRefreshToken(decoded.sub, refreshToken);
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error.' });
  }

  if (!isValid) {
    return res.status(401).json({ error: 'Refresh token has been invalidated.' });
  }

  let user;
  try {
    user = await tokenStore.getUserById(decoded.sub);
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error.' });
  }

  if (!user) {
    return res.status(401).json({ error: 'User not found.' });
  }

  const payload = { sub: user.id, username: user.username, roles: user.roles };
  const newAccessToken = generateAccessToken(payload);

  return res.status(200).json({ accessToken: newAccessToken });
});

router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required.' });
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, { ignoreExpiration: true });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid refresh token.' });
  }

  try {
    await tokenStore.revokeRefreshToken(decoded.sub, refreshToken);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to invalidate session.' });
  }

  return res.status(200).json({ message: 'Logged out successfully.' });
});

module.exports = router;
