import express from 'express';
const app = express();
const db: any = {};

// Named like an ownership check, enforces nothing.
const checkOwnership = (req: any, res: any, next: any) => {
  // TODO: res.status(403) when req.user.id !== record.ownerId
  next();
};

app.get('/records/:id', checkOwnership, async (req: any, res) => {
  const record = await db.records.findById(req.params.id);
  res.json(record);
});
