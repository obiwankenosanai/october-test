const express = require('express');
const { router: authRouter } = require('./auth/routes');
const { authenticate, authenticateWithRole } = require('./auth/middleware');
const http = require('http');

function createApp() {
  const app = express();
  app.use(express.json());

  app.use('/auth', authRouter);

  app.get('/protected', authenticate, (req, res) => {
    res.json({ message: 'Protected resource', user: req.user });
  });

  app.get('/admin', authenticateWithRole('admin'), (req, res) => {
    res.json({ message: 'Admin resource', user: req.user });
  });

  return app;
}

function createServer({ port = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const app = createApp();
    const server = http.createServer(app);
    server.listen(port, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

module.exports = { createServer, createApp };
