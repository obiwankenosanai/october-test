const { z } = require('zod');

const createSchema = z.object({
  title: z.string().min(1).max(200),
});

const updateSchema = z.object({
  title: z.string().min(1).max(200).optional(),
  completed: z.boolean().optional(),
});

module.exports = { createSchema, updateSchema };
