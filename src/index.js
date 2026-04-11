const express = require('express');
const authRoutes = require('./routes/auth');
const { authenticate } = require('./middleware/auth');
const { requireRole } = require('./middleware/requireRole');

const app = express();

app.use(express.json());

app.use('/auth', authRoutes);

app.get('/protected', authenticate, requireRole('editor'), (req, res) => {
  res.json({ message: 'Welcome, editor.', user: req.user });
});

module.exports = app;
