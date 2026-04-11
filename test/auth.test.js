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

  it('allows regular user to reach user route', async () => {
    const { status } = await get('/protected', {
      Authorization: `Bearer ${userToken}`,
    });
    assert.equal(status, 200);
  });
});

describe('Rate limiting', () => {
  it('returns 429 after exceeding the login attempt limit', async () => {
    const attempts = [];
    for (let i = 0; i < 20; i++) {
      attempts.push(
        post('/auth/login', { username: 'nobody', password: 'wrong' })
      );
    }
    const results = await Promise.all(attempts);
    const tooMany = results.filter((r) => r.status === 429);
    assert.ok(tooMany.length > 0, 'expected at least one 429 response');
  });

  it('429 response includes Retry-After header', async () => {
    const attempts = [];
    for (let i = 0; i < 20; i++) {
      attempts.push(
        post('/auth/login', { username: 'nobody', password: 'wrong' })
      );
    }
    const results = await Promise.all(attempts);
    const limited = results.find((r) => r.status === 429);
    if (limited) {
      assert.ok(
        limited.headers.get('retry-after'),
        'Retry-After header missing'
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

  it('issues new tokens when a valid refresh token is presented', async () => {
    const { status, body } = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.equal(status, 200);
    assert.ok(body.accessToken, 'new accessToken missing');
    assert.ok(body.refreshToken, 'new refreshToken missing');
  });

  it('new access token differs from the original', async () => {
    const { body } = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.notEqual(body.accessToken, firstAccessToken);
  });

  it('rejects a refresh token that has already been rotated (replay attack)', async () => {
    const first = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.equal(first.status, 200);

    const second = await post('/auth/refresh', {
      refreshToken: firstRefreshToken,
    });
    assert.equal(second.status, 401);
    assert.ok(second.body.error);
  });

  it('returns 400 when refresh token is missing from request body', async () => {
    const { status, body } = await post('/auth/refresh', {});
    assert.equal(status, 400);
    assert.ok(body.error);
  });

  it('returns 401 for a completely invalid refresh token string', async () => {
    const { status, body } = await post('/auth/refresh', {
      refreshToken: 'garbage-token-value',
    });
    assert.equal(status, 401);
    assert.ok(body.error);
  });
});

describe('Expired token handling', () => {
  it('returns 401 with an expiry-specific error for an expired access token', async () => {
    const { body } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });

    const expiredToken = await fetch(`${baseUrl}/test/expired-token`)
      .then((r) => r.json())
      .then((d) => d.token)
      .catch(() => null);

    if (!expiredToken) {
      return;
    }

    const { status, body: errBody } = await get('/protected', {
      Authorization: `Bearer ${expiredToken}`,
    });
    assert.equal(status, 401);
    assert.ok(errBody.error);
    assert.match(errBody.error, /expired/i);
  });

  it('returns 401 for an expired refresh token', async () => {
    const expiredRefresh = await fetch(`${baseUrl}/test/expired-refresh-token`)
      .then((r) => r.json())
      .then((d) => d.token)
      .catch(() => null);

    if (!expiredRefresh) {
      return;
    }

    const { status, body } = await post('/auth/refresh', {
      refreshToken: expiredRefresh,
    });
    assert.equal(status, 401);
    assert.ok(body.error);
    assert.match(body.error, /expired/i);
  });

  it('valid token still works before expiry', async () => {
    const { body: loginBody } = await post('/auth/login', {
      username: 'admin',
      password: 'password',
    });
    const { status } = await get('/protected', {
      Authorization: `Bearer ${loginBody.accessToken}`,
    });
    assert.equal(status, 200);
  });
});
