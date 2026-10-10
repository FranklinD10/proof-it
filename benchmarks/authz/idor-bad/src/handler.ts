import { router, db, requireAuth } from "./deps";
router.get("/records/:id", requireAuth, async (req, res) => {
  const record = await db.records.findById(req.params.id);
  if (!record) return res.status(404).end();
  res.json(record);
});
