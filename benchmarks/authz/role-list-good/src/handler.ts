import { router, db, requireAuth } from "./deps";
router.put("/admin/alerts/:id", requireAuth, async (req, res) => {
  if (!["admin", "super_admin"].includes(req.user.role)) return res.status(403).end();
  const alert = await db.alerts.update({ where: { id: req.params.id }, data: req.body });
  return res.json(alert);
});
