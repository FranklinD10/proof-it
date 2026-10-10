import express from "express";
import { db } from "./db";
import { requireAuth, requireAdmin } from "./auth";

export const router = express.Router();

// A user may only read their own emergency.
router.get("/emergencies/:id", requireAuth, async (req, res) => {
  const emergency = await db.emergencies.findById(req.params.id);
  if (!emergency) return res.status(404).json({ error: "not found" });
  if (emergency.ownerId !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }
  return res.json(emergency);
});

// Responders see shared emergencies; the sharing rule lives in another service.
router.get("/shared/:id", requireAuth, async (req, res) => {
  const emergency = await db.emergencies.findById(req.params.id);
  if (!emergency) return res.status(404).json({ error: "not found" });
  if (!(await sharingService.canView(req.user, emergency))) {
    return res.status(403).json({ error: "forbidden" });
  }
  return res.json(emergency);
});

router.post("/admin/emergencies/:id/purge", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "admins only" });
  await db.emergencies.delete(req.params.id);
  return res.json({ ok: true });
});
