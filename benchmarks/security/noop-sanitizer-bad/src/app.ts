import express from 'express';
const app = express();
const db: any = {};

// Named like a sanitizer, returns its input unchanged.
function sanitizeInput(x: string) {
  return x;
}

app.get('/search', async (req, res) => {
  const q = sanitizeInput(req.query.q as string);
  res.json(await db.query(`SELECT * FROM items WHERE name = '${q}'`));
});
