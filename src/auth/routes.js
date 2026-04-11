const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { validateCredentials } = require('./userService');
const { tokenStore } = require('./tokenStore');
const { generateAccessToken, generateRefreshToken } = require('./tokenUtils');

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  let user;
  try {
    user = await validateCredentials(username, password);
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  tokenStore.add(refreshToken, user.id);

  return res.status(200).json({ accessToken, refreshToken });
});

router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  if (!tokenStore.has(refreshToken)) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  let payload;
  try {
    payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    tokenStore.remove(refreshToken);
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const user = { id: payload.sub, role: payload.role };
  const accessToken = generateAccessToken(user);

  return res.status(200).json({ accessToken });
});

router.post('/logout', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  if (!tokenStore.has(refreshToken)) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  tokenStore.remove(refreshToken);

  return res.status(200).json({ message: 'Logged out successfully' });
});

module.exports = router;
