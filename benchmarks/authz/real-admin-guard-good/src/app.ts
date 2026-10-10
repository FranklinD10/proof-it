import express from 'express';
const app = express();
const db: any = {};

const requireRole = (...roles: string[]) => (req: any, res: any, next: any) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
};

app.delete('/admin/users/:id', requireRole('admin'), async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
});
