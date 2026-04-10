const express = require('express');
const router = express.Router();
const store = require('./store');

router.get('/todos', (req, res) => {
  res.json(store.getAll());
});

router.get('/todos/:id', (req, res) => {
  const todo = store.getById(req.params.id);
  if (!todo) {
    return res.status(404).json({ error: 'Todo not found' });
  }
  res.json(todo);
});

router.post('/todos', (req, res) => {
  const { title, completed } = req.body;
  if (!title || typeof title !== 'string' || title.trim() === '') {
    return res.status(400).json({ error: 'title is required' });
  }
  const todo = store.create({ title: title.trim(), completed: completed === true });
  res.status(201).json(todo);
});

router.patch('/todos/:id', (req, res) => {
  const todo = store.getById(req.params.id);
  if (!todo) {
    return res.status(404).json({ error: 'Todo not found' });
  }
  const { title, completed } = req.body;
  const updates = {};
  if (title !== undefined) {
    if (typeof title !== 'string' || title.trim() === '') {
      return res.status(400).json({ error: 'title must be a non-empty string' });
    }
    updates.title = title.trim();
  }
  if (completed !== undefined) {
    if (typeof completed !== 'boolean') {
      return res.status(400).json({ error: 'completed must be a boolean' });
    }
    updates.completed = completed;
  }
  const updated = store.update(req.params.id, updates);
  res.json(updated);
});

router.delete('/todos/:id', (req, res) => {
  const todo = store.getById(req.params.id);
  if (!todo) {
    return res.status(404).json({ error: 'Todo not found' });
  }
  store.remove(req.params.id);
  res.status(204).send();
});

module.exports = router;
