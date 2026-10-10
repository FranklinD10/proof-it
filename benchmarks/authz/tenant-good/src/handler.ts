import { router, db, requireAuth } from "./deps";
// Multi-tenant: users may only read their own organization.
router.get("/organizations/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  if (req.user.role !== "super_admin") {
    const userOrgId = req.user.organizationId;
    if (userOrgId !== id) return res.status(403).json({ error: "Access denied" });
  }
  const organization = await db.organization.findUnique({ where: { id } });
  if (!organization) return res.status(404).end();
  return res.json(organization);
});
