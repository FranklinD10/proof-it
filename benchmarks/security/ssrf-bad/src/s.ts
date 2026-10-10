export async function proxy(req: any) { return fetch(req.query.url); }
