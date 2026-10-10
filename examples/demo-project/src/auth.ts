export function requireAuth(req: any, _res: any, next: () => void) {
  if (!req.user) throw new Error("unauthenticated");
  next();
}
export function requireAdmin(req: any, _res: any, next: () => void) {
  if (req.user?.role !== "admin") throw new Error("forbidden");
  next();
}
