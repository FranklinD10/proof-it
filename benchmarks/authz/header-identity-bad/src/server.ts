// Identity copied from a client-controlled header: NOT trusted.
export function appendUserId() {
  return (req: any, res: any, next: any) => {
    req.body.UserId = req.headers["x-user-id"];
    next();
  };
}
app.get("/api/Addresss/:id", isAuthorized(), appendUserId(), async (req, res) => {
  const addresses = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });
  res.json({ data: addresses });
});
