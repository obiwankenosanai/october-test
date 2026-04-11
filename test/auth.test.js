const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('../src/server');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const ACCESS_SECRET = 'test-access-secret-32byteslong!!!';
const REFRESH_SECRET = 'test-refresh-secret-32byteslong!!';

const testUsers = [
  {
    id: '1',
    username: 'admin',
    role: 'admin',
    salt: 'testsalt1',
    passwordHash: '',
  },
  {
    id: '2',
    username: 'user',
    role: 'viewer',
    salt: 'testsalt2',
    passwordHash: '',
  },
];

async function pbkdf2(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derived) => {
      if (err) reject(err);
      else resolve(derived.toString('hex'));
    });
  });
}

let server;
let baseUrl;

before(async () => {
  testUsers[0].passwordHash = await pbkdf2('password', testUsers[0].salt);
  testUsers[1].passwordHash = await pbkdf2('password', testUsers[1].salt);

  process.env.ACCESS_TOKEN_SECRET = ACCESS_SECRET;
  process.env.REFRESH_TOKEN_SECRET = REFRESH_SECRET;
  process.env.ACCESS_TOKEN_EXPIRES_IN = '15m';
  process.env.AUTH_USERS = JSON.stringify(testUsers);

  server = await createServer({ port: 0 });
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await new Promise((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve()))
  );
});

async function post(path, body, headers = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, body: json, headers: res.headers };
}

async function get(path, headers = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'GET',
    headers,
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, body: json, headers: res.headers };
}

describe('Login flow', () => {
  it('returns 400 when credentials are missing', async () => {
    const { status, body } = await post('/auth/login', {});
    assert.equal(status, 400);
    assert.ok(body.error);
  });

  it('returns 401 for invalid credentials', async () => {
    const { status, body } = await post('/auth/login', {
      username: 'nobody',
      password: 'wrong',
    });
    assert.equal(status, 401);
    assert.ok(body.error);
  });

  it('returns access and refresh tokens on valid login', async () => {
    const { status, body } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    assert.equal(status, 200);
    assert.ok(body.accessToken, 'accessToken missing');
    assert.ok(body.refreshToken, 'refreshToken missing');
  });

  it('access token is a three-part JWT string', async () => {
    const { body } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    const parts = body.accessToken.split('.');
    assert.equal(parts.length, 3);
  });
});

describe('Token verification', () => {
  let accessToken;

  before(async () => {
    const { body } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    accessToken = body.accessToken;
  });

  it('allows access to protected route with valid token', async () => {
    const { status } = await get('/protected', {
      Authorization: `Bearer ${accessToken}`,
    });
    assert.equal(status, 200);
  });

  it('returns 401 when Authorization header is absent', async () => {
    const { status, body } = await get('/protected');
    assert.equal(status, 401);
    assert.ok(body.error);
  });

  it('returns 401 for a malformed token', async () => {
    const { status, body } = await get('/protected', {
      Authorization: 'Bearer not.a.token',
    });
    assert.equal(status, 401);
    assert.ok(body.error);
  });

  it('returns 401 for a token with a bad signature', async () => {
    const [header, payload] = accessToken.split('.');
    const tampered = `${header}.${payload}.badsignature`;
    const { status, body } = await get('/protected', {
      Authorization: `Bearer ${tampered}`,
    });
    assert.equal(status, 401);
    assert.ok(body.error);
  });
});

describe('Role-based access control', () => {
  let adminToken;
  let userToken;

  before(async () => {
    const adminRes = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    adminToken = adminRes.body.accessToken;

    const userRes = await post('/auth/login', {
      username: 'user',
      password: 'password',
    });
    userToken = userRes.body.accessToken;
  });

  it('allows admin to reach admin-only route', async () => {
    const { status } = await get('/admin', {
      Authorization: `Bearer ${adminToken}`,
    });
    assert.equal(status, 200);
  });

  it('rejects non-admin user from admin-only route with 403', async () => {
    const { status, body } = await get('/admin', {
      Authorization: `Bearer ${userToken}`,
    });
    assert.equal(status, 403);
    assert.ok(body.error);
  });

  it('allows viewer to reach unprotected-by-role route', async () => {
    const { status } = await get('/protected', {
      Authorization: `Bearer ${userToken}`,
    });
    assert.equal(status, 200);
  });
});

describe('Rate limiting', () => {
  it('returns 429 after exceeding login rate limit', async () => {
    const loginRateLimitServer = await createServer({ port: 0 });
    const { port } = loginRateLimitServer.address();
    const rlBase = `http://127.0.0.1:${port}`;

    let lastStatus;
    for (let i = 0; i < 15; i++) {
      const res = await fetch(`${rlBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'nobody', password: 'wrong' }),
      });
      lastStatus = res.status;
      if (lastStatus === 429) break;
    }

    assert.equal(lastStatus, 429);

    await new Promise((resolve, reject) =>
      loginRateLimitServer.close((err) => (err ? reject(err) : resolve()))
    );
  });

  it('response includes Retry-After header when rate limited', async () => {
    const rlServer = await createServer({ port: 0 });
    const { port } = rlServer.address();
    const rlBase = `http://127.0.0.1:${port}`;

    let retryAfter;
    for (let i = 0; i < 15; i++) {
      const res = await fetch(`${rlBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'nobody', password: 'wrong' }),
      });
      if (res.status === 429) {
        retryAfter = res.headers.get('retry-after');
        break;
      }
    }

    assert.ok(retryAfter, 'Retry-After header missing');
    assert.ok(Number(retryAfter) > 0, 'Retry-After should be positive');

    await new Promise((resolve, reject) =>
      rlServer.close((err) => (err ? reject(err) : resolve()))
    );
  });
});

describe('Refresh token rotation', () => {
  let refreshToken;
  let accessToken;

  before(async () => {
    const { body } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    accessToken = body.accessToken;
    refreshToken = body.refreshToken;
  });

  it('returns new tokens when a valid refresh token is submitted', async () => {
    const { status, body } = await post('/auth/refresh', { refreshToken });
    assert.equal(status, 200);
    assert.ok(body.accessToken, 'new accessToken missing');
    assert.ok(body.refreshToken, 'new refreshToken missing');
  });

  it('old refresh token is invalidated after rotation', async () => {
    const firstLogin = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    const originalRefresh = firstLogin.body.refreshToken;

    const firstRefresh = await post('/auth/refresh', { refreshToken: originalRefresh });
    assert.equal(firstRefresh.status, 200);

    const secondRefresh = await post('/auth/refresh', { refreshToken: originalRefresh });
    assert.equal(secondRefresh.status, 401);
    assert.ok(secondRefresh.body.error);
  });

  it('returns 401 for a tampered refresh token', async () => {
    const { status, body } = await post('/auth/refresh', {
      refreshToken: 'totally.fake.token',
    });
    assert.equal(status, 401);
    assert.ok(body.error);
  });

  it('returns 400 when refresh token is missing', async () => {
    const { status, body } = await post('/auth/refresh', {});
    assert.equal(status, 400);
    assert.ok(body.error);
  });
});

describe('Expired token handling', () => {
  it('returns 401 with expired-token error for an expired access token', async () => {
    const expiredToken = jwt.sign(
      { sub: '1', username: 'admin', role: 'admin' },
      ACCESS_SECRET,
      { expiresIn: -1 }
    );

    const { status, body } = await get('/protected', {
      Authorization: `Bearer ${expiredToken}`,
    });
    assert.equal(status, 401);
    assert.ok(body.error);
    assert.match(body.error, /expired/i);
  });

  it('returns 401 for an expired refresh token', async () => {
    const loginRes = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    const validRefresh = loginRes.body.refreshToken;

    const { status, body } = await post('/auth/refresh', {
      refreshToken: validRefresh + 'corrupted',
    });
    assert.equal(status, 401);
    assert.ok(body.error);
  });
});
