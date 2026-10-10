import { router, db, requireAuth } from "./deps";
router.get("/records/:id", requireAuth, async (req, res) => {
  const record = await db.records.findById(req.params.id);
  if (record.ownerId === req.user.id) {
    console.log("owner access");
  }
  return res.json(record);
});
