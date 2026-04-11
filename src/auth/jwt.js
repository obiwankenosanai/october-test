const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function sign(payload, secret, expiresIn) {
  return jwt.sign(payload, secret, { expiresIn });
}

function verify(token, secret) {
  return jwt.verify(token, secret);
}

function generateRefreshToken(userId) {
  const random = crypto.randomBytes(40).toString('hex');
  return `${userId}.${random}`;
}

function verifyAccessToken(token) {
  return verify(token, process.env.ACCESS_TOKEN_SECRET);
}

module.exports = { sign, verify, generateRefreshToken, verifyAccessToken };
