const express = require('express');
const todoRoutes = require('./routes/todos');

const app = express();

app.use(express.json());

app.use('/todos', todoRoutes);

app.use((err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  res.status(status).json({ error: message });
});

module.exports = app;
