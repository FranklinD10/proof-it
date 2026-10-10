import express from 'express';
const app = express();
const db: any = {};

// Named like an admin guard, enforces nothing.
const requireAdmin = (req: any, res: any, next: any) => next();

app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
});
