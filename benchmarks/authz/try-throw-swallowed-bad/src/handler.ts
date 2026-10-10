import { router, db, requireAuth } from "./deps";
// The ownership check throws, but the catch swallows it and execution continues.
router.get("/records/:id", requireAuth, async (req, res) => {
  const record = await db.records.findById(req.params.id);
  try {
    if (record.ownerId !== req.user.id) throw new Error("forbidden");
  } catch (e) {
    console.warn(e);
  }
  return res.json(record);
});
