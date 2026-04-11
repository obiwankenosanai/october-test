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

  it('returns accessToken and refreshToken on valid login', async () => {
    const { status, body } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    assert.equal(status, 200);
    assert.ok(body.accessToken, 'accessToken should be present');
    assert.ok(body.refreshToken, 'refreshToken should be present');
    assert.equal(typeof body.accessToken, 'string');
    assert.equal(typeof body.refreshToken, 'string');
  });

  it('accessToken is a three-part JWT', async () => {
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
    const parts = accessToken.split('.');
    parts[2] = parts[2].split('').reverse().join('');
    const tampered = parts.join('.');
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

  it('allows admin to access admin-only route', async () => {
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

  it('allows regular user to access user route', async () => {
    const { status } = await get('/protected', {
      Authorization: `Bearer ${userToken}`,
    });
    assert.equal(status, 200);
  });
});

describe('Rate limiting', () => {
  it('returns 429 after exceeding login attempt threshold', async () => {
    const attempts = [];
    for (let i = 0; i < 20; i++) {
      attempts.push(
        post('/auth/login', { username: 'nobody', password: 'wrong' })
      );
    }
    const results = await Promise.all(attempts);
    const tooMany = results.filter((r) => r.status === 429);
    assert.ok(tooMany.length > 0, 'Expected at least one 429 response');
  });

  it('429 response includes Retry-After header', async () => {
    const attempts = [];
    for (let i = 0; i < 20; i++) {
      attempts.push(
        post('/auth/login', { username: 'nobody', password: 'wrong' })
      );
    }
    const results = await Promise.all(attempts);
    const tooMany = results.filter((r) => r.status === 429);
    if (tooMany.length > 0) {
      const retryAfter = tooMany[0].headers.get('retry-after');
      assert.ok(retryAfter !== null, 'Retry-After header should be present');
      assert.ok(Number(retryAfter) > 0, 'Retry-After should be a positive number');
    }
  });
});

describe('Refresh token rotation', () => {
  let refreshToken;
  let accessToken;

  before(async () => {
    const { body } = await post('/auth/login', {
      username: 'user',
      password: 'password',
    });
    refreshToken = body.refreshToken;
    accessToken = body.accessToken;
  });

  it('issues new tokens when a valid refresh token is presented', async () => {
    const { status, body } = await post('/auth/refresh', { refreshToken });
    assert.equal(status, 200);
    assert.ok(body.accessToken);
    assert.ok(body.refreshToken);
  });

  it('new refresh token differs from the old one (rotation)', async () => {
    const { body } = await post('/auth/refresh', { refreshToken });
    const newRefreshToken = body.refreshToken;
    const { body: body2 } = await post('/auth/refresh', {
      refreshToken: newRefreshToken,
    });
    assert.notEqual(newRefreshToken, body2.refreshToken);
  });

  it('rejects a refresh token that has already been rotated', async () => {
    const first = await post('/auth/refresh', { refreshToken });
    assert.equal(first.status, 200);
    const second = await post('/auth/refresh', { refreshToken });
    assert.equal(second.status, 401);
    assert.ok(second.body.error);
  });

  it('returns 400 when refreshToken field is missing', async () => {
    const { status, body } = await post('/auth/refresh', {});
    assert.equal(status, 400);
    assert.ok(body.error);
  });

  it('returns 401 for a completely invalid refresh token', async () => {
    const { status, body } = await post('/auth/refresh', {
      refreshToken: 'garbage-token',
    });
    assert.equal(status, 401);
    assert.ok(body.error);
  });
});

describe('Expired token handling', () => {
  it('returns 401 with expiry message for an expired access token', async () => {
    const { body: loginBody } = await post('/auth/login', {
      username: 'user',
      password: 'password',
      __test_expire_immediately: true,
    });
    assert.ok(loginBody.accessToken, 'Should receive an access token');

    await new Promise((resolve) => setTimeout(resolve, 1100));

    const { status, body } = await get('/protected', {
      Authorization: `Bearer ${loginBody.accessToken}`,
    });
    assert.equal(status, 401);
    assert.ok(body.error);
    assert.match(body.error, /expired/i);
  });

  it('expired refresh token is rejected', async () => {
    const { body: loginBody } = await post('/auth/login', {
      username: 'user',
      password: 'password',
      __test_expire_immediately: true,
    });
    assert.ok(loginBody.refreshToken);

    await new Promise((resolve) => setTimeout(resolve, 1100));

    const { status, body } = await post('/auth/refresh', {
      refreshToken: loginBody.refreshToken,
    });
    assert.equal(status, 401);
    assert.ok(body.error);
    assert.match(body.error, /expired/i);
  });
});
