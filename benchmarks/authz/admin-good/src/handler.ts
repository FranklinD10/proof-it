import { router, requireAuth, purge } from "./deps";
router.post("/admin/purge", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "admins only" });
  await purge();
  res.json({ ok: true });
});
