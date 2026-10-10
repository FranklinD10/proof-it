import express from 'express';
import { requireAdmin } from '@acme/auth-middleware';
const app = express();
const db: any = {};

// The guard lives in a library: Proof-It cannot see what it checks.
app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
});
