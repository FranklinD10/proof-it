import express from "express";
import { db } from "./db";
import { requireAuth } from "./auth";

export const router = express.Router();

router.get("/emergencies/:id", requireAuth, async (req, res) => {
  const emergency = await db.emergencies.findById(req.params.id);
  if (!emergency) return res.status(404).json({ error: "not found" });
  if (emergency.ownerId !== req.user.id) return res.status(403).json({ error: "forbidden" });
  return res.json(emergency);
});
