// Juice Shop style: middleware overwrites req.body.UserId with the authenticated user.
export function appendUserId() {
  return (req: any, res: any, next: any) => {
    req.body.UserId = tokenMap[jwtFrom(req)].data.id;
    next();
  };
}
app.get("/api/Addresss/:id", isAuthorized(), appendUserId(), async (req, res) => {
  const addresses = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });
  res.json({ data: addresses });
});
