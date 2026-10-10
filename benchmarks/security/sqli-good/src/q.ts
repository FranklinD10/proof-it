export async function search(req: any, db: any) {
  return db.query("SELECT * FROM items WHERE name LIKE $1", [`%${req.query.q}%`]);
}
