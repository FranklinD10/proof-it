import { router, requireAuth, purge } from "./deps";
router.post("/admin/purge", requireAuth, async (req, res) => {
  await purge();
  res.json({ ok: true });
});
