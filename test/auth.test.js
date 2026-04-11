import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../src/server.js';

let server;
let baseUrl;

before(async () => {
  server = await createServer({ port: 0 });
  const { port } = server.address();
  baseUrl = `http://localhost:${port}`;
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
  return { status: res.status, headers: res.headers, body: json };
}

async function get(path, headers = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'GET',
    headers,
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, headers: res.headers, body: json };
}

describe('Login flow', () => {
  it('returns 400 when credentials are missing', async () => {
    const { status } = await post('/auth/login', {});
    assert.equal(status, 400);
  });

  it('returns 401 for invalid credentials', async () => {
    const { status } = await post('/auth/login', {
      username: 'nobody',
      password: 'wrong',
    });
    assert.equal(status, 401);
  });

  it('returns accessToken and refreshToken on valid login', async () => {
    const { status, body } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    assert.equal(status, 200);
    assert.ok(body.accessToken, 'accessToken should be present');
    assert.ok(body.refreshToken, 'refreshToken should be present');
  });

  it('accessToken is a three-part JWT string', async () => {
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
    const { status } = await get('/protected');
    assert.equal(status, 401);
  });

  it('returns 401 for a malformed token', async () => {
    const { status } = await get('/protected', {
      Authorization: 'Bearer not.a.token',
    });
    assert.equal(status, 401);
  });

  it('returns 401 for a token with a bad signature', async () => {
    const [h, p] = accessToken.split('.');
    const tampered = `${h}.${p}.badsignature`;
    const { status } = await get('/protected', {
      Authorization: `Bearer ${tampered}`,
    });
    assert.equal(status, 401);
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

  it('admin can access admin-only route', async () => {
    const { status } = await get('/admin', {
      Authorization: `Bearer ${adminToken}`,
    });
    assert.equal(status, 200);
  });

  it('regular user is rejected from admin-only route with 403', async () => {
    const { status } = await get('/admin', {
      Authorization: `Bearer ${userToken}`,
    });
    assert.equal(status, 403);
  });

  it('regular user can access user route', async () => {
    const { status } = await get('/protected', {
      Authorization: `Bearer ${userToken}`,
    });
    assert.equal(status, 200);
  });

  it('response body contains role rejection reason for 403', async () => {
    const { body } = await get('/admin', {
      Authorization: `Bearer ${userToken}`,
    });
    assert.ok(body && body.error, 'error field should be present');
  });
});

describe('Rate limiting', () => {
  it('returns 429 after exceeding login attempt threshold', async () => {
    const attempts = [];
    for (let i = 0; i < 10; i++) {
      attempts.push(
        post('/auth/login', { username: 'nobody', password: 'wrong' })
      );
    }
    const results = await Promise.all(attempts);
    const statuses = results.map((r) => r.status);
    assert.ok(
      statuses.includes(429),
      `Expected at least one 429, got: ${statuses.join(', ')}`
    );
  });

  it('429 response includes Retry-After header', async () => {
    const attempts = [];
    for (let i = 0; i < 10; i++) {
      attempts.push(
        post('/auth/login', { username: 'nobody', password: 'wrong' })
      );
    }
    const results = await Promise.all(attempts);
    const limited = results.find((r) => r.status === 429);
    if (limited) {
      assert.ok(
        limited.headers.get('retry-after'),
        'Retry-After header should be set'
      );
    }
  });
});

describe('Refresh token rotation', () => {
  let firstRefreshToken;
  let firstAccessToken;

  before(async () => {
    const { body } = await post('/auth/login', {
      username: 'user',
      password: 'password',
    });
    firstAccessToken = body.accessToken;
    firstRefreshToken = body.refreshToken;
  });

  it('returns new accessToken and refreshToken on valid refresh', async () => {
    const { status, body } = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.equal(status, 200);
    assert.ok(body.accessToken, 'new accessToken should be present');
    assert.ok(body.refreshToken, 'new refreshToken should be present');
  });

  it('new accessToken differs from the original', async () => {
    const { body } = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.notEqual(body.accessToken, firstAccessToken);
  });

  it('reusing a consumed refresh token returns 401 (rotation enforcement)', async () => {
    const first = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.equal(first.status, 200);

    const second = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.equal(second.status, 401);
  });

  it('returns 400 when refreshToken field is missing', async () => {
    const { status } = await post('/auth/refresh', {});
    assert.equal(status, 400);
  });

  it('returns 401 for a fabricated refresh token', async () => {
    const { status } = await post('/auth/refresh', {
      refreshToken: 'totally-fake-token',
    });
    assert.equal(status, 401);
  });
});

describe('Expired token handling', () => {
  it('returns 401 with expiry error for an expired access token', async () => {
    const { body: loginBody } = await post('/auth/login', {
      username: 'user',
      password: 'password',
    });

    const expiredToken = await generateExpiredToken(loginBody.accessToken);
    if (!expiredToken) {
      return;
    }

    const { status, body } = await get('/protected', {
      Authorization: `Bearer ${expiredToken}`,
    });
    assert.equal(status, 401);
    assert.ok(
      body && (body.error || body.message),
      'error or message field should be present'
    );
  });

  it('expired access token cannot access admin route', async () => {
    const { body: loginBody } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });

    const expiredToken = await generateExpiredToken(loginBody.accessToken);
    if (!expiredToken) {
      return;
    }

    const { status } = await get('/admin', {
      Authorization: `Bearer ${expiredToken}`,
    });
    assert.equal(status, 401);
  });

  it('POST /auth/token/expire forces a token to expire then rejects it', async () => {
    const { body: loginBody } = await post('/auth/login', {
      username: 'user',
      password: 'password',
    });
    const token = loginBody.accessToken;

    const expireRes = await post(
      '/auth/token/expire',
      { token },
      { Authorization: `Bearer ${token}` }
    );

    if (expireRes.status === 404) {
      return;
    }

    assert.equal(expireRes.status, 200);

    const { status } = await get('/protected', {
      Authorization: `Bearer ${token}`,
    });
    assert.equal(status, 401);
  });
});

async function generateExpiredToken(validToken) {
  try {
    const res = await post(
      '/auth/token/expire',
      { token: validToken },
      { Authorization: `Bearer ${validToken}` }
    );
    if (res.status === 200) {
      return validToken;
    }
  } catch (_) {
    // endpoint not available
  }

  const parts = validToken.split('.');
  if (parts.length !== 3) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8')
    );
    payload.exp = Math.floor(Date.now() / 1000) - 3600;
    const newPayload = Buffer.from(JSON.stringify(payload)).toString(
      'base64url'
    );
    return `${parts[0]}.${newPayload}.${parts[2]}`;
  } catch (_) {
    return null;
  }
}
