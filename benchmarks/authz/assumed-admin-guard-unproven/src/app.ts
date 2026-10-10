import express from 'express';
const app = express();
const db: any = {};

// Reads the role and can deny, but never says WHICH role is required:
// "only admins pass" would be an assumption, not something the code shows.
const isAdmin = (req: any, res: any, next: any) => {
  if (!req.user || !req.user.role) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
};

app.delete('/admin/users/:id', isAdmin, async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
});
