const store = new Map();

function rateLimiter({ windowMs = 60000, max = 100 } = {}) {
  return function (req, res, next) {
    const key = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();

    let record = store.get(key);

    if (!record || now > record.resetAt) {
      record = { count: 1, resetAt: now + windowMs };
      store.set(key, record);
      return next();
    }

    record.count += 1;

    if (record.count > max) {
      const retryAfterSec = Math.ceil((record.resetAt - now) / 1000);
      res.set('Retry-After', String(retryAfterSec));
      return res.status(429).json({
        error: 'Too Many Requests',
        retryAfter: retryAfterSec,
      });
    }

    return next();
  };
}

module.exports = rateLimiter;
