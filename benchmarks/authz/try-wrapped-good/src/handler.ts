import { router, db, requireAuth } from "./deps";
router.get("/records/:id", requireAuth, async (req, res) => {
  try {
    const record = await db.records.findById(req.params.id);
    if (!record) return res.status(404).end();
    if (record.ownerId !== req.user.id) return res.status(403).json({ error: "forbidden" });
    return res.json(record);
  } catch (e) {
    res.status(500).json({ error: "failed" });
  }
});
