import { router, db, requireAuth } from "./deps";
router.post("/records/:id/share", requireAuth, async (req, res) => {
  const { email, note } = req.body;
  if (!email || !note) return res.status(400).json({ error: "email and note are required" });
  const record = await db.records.findById(req.params.id);
  if (!record || record.ownerId !== req.user.id) return res.status(404).end();
  return res.json(record);
});
