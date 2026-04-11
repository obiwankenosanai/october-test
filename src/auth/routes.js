const express = require('express');
const router = express.Router();
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require('./tokenService');
const { validateCredentials } = require('./userService');
const { invalidateRefreshToken, isRefreshTokenValid } = require('./tokenStore');

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

  return res.status(200).json({ accessToken, refreshToken });
});

router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const isValid = await isRefreshTokenValid(refreshToken);
  if (!isValid) {
    return res.status(401).json({ error: 'Refresh token has been invalidated' });
  }

  const accessToken = generateAccessToken({ id: payload.id, username: payload.username, role: payload.role });

  return res.status(200).json({ accessToken });
});

router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  try {
    verifyRefreshToken(refreshToken);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  try {
    await invalidateRefreshToken(refreshToken);
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }

  return res.status(200).json({ message: 'Logged out successfully' });
});

module.exports = router;
