export function requireAuth(req: any, _res: any, next: () => void) {
  if (!req.user) throw new Error("unauthenticated");
  next();
}
