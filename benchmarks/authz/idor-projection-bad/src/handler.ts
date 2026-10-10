import { router, db, requireAuth } from "./deps";
// Leaks a projection of another user's record (fields copied into a new object).
router.get("/emergencies/:id/location", requireAuth, async (req, res) => {
  const emergency = await db.emergencies.findById(req.params.id);
  if (!emergency) return res.status(404).json({ error: "not found" });
  const location = { lat: emergency.lat, lng: emergency.lng };
  return res.json(location);
});
