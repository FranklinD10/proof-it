import { router, db, requireAuth } from "./deps";
router.get("/records/:id", requireAuth, async (req, res) => {
  const record = await db.records.findOne({ where: { id: req.params.id, userId: req.user.id } });
  if (!record) return res.status(404).end();
  return res.json(record);
});
