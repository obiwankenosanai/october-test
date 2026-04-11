const express = require('express');
const crypto = require('crypto');
const { sign, generateRefreshToken, verifyAccessToken } = require('./jwt');
const rateLimiter = require('./rate-limit');

const router = express.Router();

const loginRateLimiter = rateLimiter({ windowMs: 60000, max: 10 });
const refreshRateLimiter = rateLimiter({ windowMs: 60000, max: 30 });
const logoutRateLimiter = rateLimiter({ windowMs: 60000, max: 30 });

// In-memory refresh token store: token -> { userId, role, expiresAt }
const refreshTokenStore = new Map();

const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function pruneExpiredTokens() {
  const now = Date.now();
  for (const [token, record] of refreshTokenStore.entries()) {
    if (now > record.expiresAt) {
      refreshTokenStore.delete(token);
    }
  }
}

setInterval(pruneExpiredTokens, 60 * 60 * 1000).unref();

function getUsers() {
  const raw = process.env.AUTH_USERS;
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function timingSafeStringEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still do a comparison to avoid timing leak on length
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derived) => {
      if (err) reject(err);
      else resolve(derived.toString('hex'));
    });
  });
}

async function validateCredentials(username, password) {
  const users = getUsers();
  const user = users.find((u) => u.username === username);
  if (!user) {
    // Perform dummy hash to avoid timing oracle on username existence
    await hashPassword(password, 'dummy-salt-000000000000000000000000');
    return null;
  }
  const hash = await hashPassword(password, user.salt);
  if (!timingSafeStringEqual(hash, user.passwordHash)) {
    return null;
  }
  return { id: user.id, username: user.username, role: user.role };
}

function makeAccessToken(user) {
  const secret = process.env.ACCESS_TOKEN_SECRET;
  if (!secret) throw new Error('ACCESS_TOKEN_SECRET is not set');
  return sign(
    { sub: user.id, username: user.username, role: user.role },
    secret,
    process.env.ACCESS_TOKEN_EXPIRES_IN || '15m'
  );
}

function makeRefreshToken(user) {
  const opaque = generateRefreshToken(user.id);
  const secret = process.env.REFRESH_TOKEN_SECRET;
  if (!secret) throw new Error('REFRESH_TOKEN_SECRET is not set');
  const hmac = crypto.createHmac('sha256', secret).update(opaque).digest('hex');
  const signed = `${opaque}.${hmac}`;
  return signed;
}

function verifyRefreshTokenSignature(signed) {
  const lastDot = signed.lastIndexOf('.');
  if (lastDot === -1) return false;
  const opaque = signed.slice(0, lastDot);
  const providedHmac = signed.slice(lastDot + 1);
  const secret = process.env.REFRESH_TOKEN_SECRET;
  if (!secret) return false;
  const expectedHmac = crypto.createHmac('sha256', secret).update(opaque).digest('hex');
  const expectedBuf = Buffer.from(expectedHmac, 'hex');
  let providedBuf;
  try {
    providedBuf = Buffer.from(providedHmac, 'hex');
  } catch {
    return false;
  }
  if (providedBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, providedBuf);
}

router.post('/login', loginRateLimiter, async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    return res.status(500).json({ error: 'Server configuration error' });
  }

  let user;
  try {
    user = await validateCredentials(username, password);
  } catch {
    return res.status(500).json({ error: 'Internal server error' });
  }

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  let accessToken, refreshToken;
  try {
    accessToken = makeAccessToken(user);
    refreshToken = makeRefreshToken(user);
  } catch {
    return res.status(500).json({ error: 'Internal server error' });
  }

  refreshTokenStore.set(refreshToken, {
    userId: user.id,
    role: user.role,
    username: user.username,
    expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
  });

  return res.status(200).json({ accessToken, refreshToken });
});

router.post('/refresh', refreshRateLimiter, (req, res) => {
  const { refreshToken } = req.body || {};

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  let signatureValid;
  try {
    signatureValid = verifyRefreshTokenSignature(refreshToken);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  if (!signatureValid) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const record = refreshTokenStore.get(refreshToken);
  if (!record) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  if (Date.now() > record.expiresAt) {
    refreshTokenStore.delete(refreshToken);
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    return res.status(500).json({ error: 'Server configuration error' });
  }

  const user = { id: record.userId, username: record.username, role: record.role };

  let newAccessToken, newRefreshToken;
  try {
    newAccessToken = makeAccessToken(user);
    newRefreshToken = makeRefreshToken(user);
  } catch {
    return res.status(500).json({ error: 'Internal server error' });
  }

  // Rotate: invalidate old, store new
  refreshTokenStore.delete(refreshToken);
  refreshTokenStore.set(newRefreshToken, {
    userId: user.id,
    role: user.role,
    username: user.username,
    expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
  });

  return res.status(200).json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
});

router.post('/logout', logoutRateLimiter, (req, res) => {
  const { refreshToken } = req.body || {};

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  let signatureValid;
  try {
    signatureValid = verifyRefreshTokenSignature(refreshToken);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  if (!signatureValid) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  if (!refreshTokenStore.has(refreshToken)) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  refreshTokenStore.delete(refreshToken);

  return res.status(200).json({ message: 'Logged out successfully' });
});

module.exports = router;
