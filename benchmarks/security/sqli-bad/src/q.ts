export async function search(req: any, db: any) {
  const term = req.query.q;
  return db.query(`SELECT * FROM items WHERE name LIKE '%${term}%'`);
}
