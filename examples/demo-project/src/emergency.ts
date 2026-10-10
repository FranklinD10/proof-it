export type EmergencyStatus = "CREATED" | "ACTIVE" | "RESOLVED" | "CANCELLED";

export interface Emergency {
  id: number;
  ownerId: number;
  status: EmergencyStatus;
}

/** The only legal lifecycle edges. */
const ALLOWED: Record<EmergencyStatus, EmergencyStatus[]> = {
  CREATED: ["ACTIVE", "CANCELLED"],
  ACTIVE: ["RESOLVED", "CANCELLED"],
  RESOLVED: [],
  CANCELLED: [],
};

export function transition(e: Emergency, next: EmergencyStatus): void {
  if (!ALLOWED[e.status].includes(next)) {
    throw new Error(`illegal transition ${e.status} -> ${next}`);
  }
  e.status = next;
}

export function createEmergency(id: number, ownerId: number): Emergency {
  const e: Emergency = { id, ownerId, status: "CREATED" };
  return e;
}

/**
 * Support tooling: administrators can re-open an emergency that was closed by mistake.
 * (Added later; this bypasses the lifecycle table.)
 */
export function reopenEmergency(e: Emergency, actorRole: string): void {
  if (actorRole !== "admin") throw new Error("admins only");
  if (e.status === "CANCELLED") throw new Error("cancelled emergencies cannot be reopened");
  e.status = "ACTIVE";
}
