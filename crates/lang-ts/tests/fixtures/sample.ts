import express from "express";
import { db } from "./db";

export type EmergencyStatus = "CREATED" | "ACTIVE" | "RESOLVED" | "CANCELLED";
const ALLOWED: Record<EmergencyStatus, EmergencyStatus[]> = {
  CREATED: ["ACTIVE", "CANCELLED"],
  ACTIVE: ["RESOLVED", "CANCELLED"],
  RESOLVED: [],
  CANCELLED: [],
};

export function transition(e: { status: EmergencyStatus }, next: EmergencyStatus) {
  if (!ALLOWED[e.status].includes(next)) throw new Error("illegal");
  e.status = next;
}

export function reopen(e: { status: EmergencyStatus }) {
  if (e.status === "CANCELLED") throw new Error("no");
  e.status = "ACTIVE";
}

export function transfer(from: { balance: number }, to: { balance: number }, amount: number) {
  if (amount <= 0) throw new Error("bad amount");
  from.balance -= amount;
  to.balance += amount;
}

const router = express.Router();
router.get("/records/:id", requireAuth, async (req, res) => {
  const record = await db.records.findById(req.params.id);
  if (!record) return res.status(404).json({ error: "not found" });
  res.json(record);
});
router.get("/safe/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const record = await db.records.findById(id);
  if (!record) return res.status(404).end();
  if (record.ownerId !== userId) return res.status(403).json({ error: "forbidden" });
  return res.json(record);
});
