module.exports.userEditSubmit = function (req, res) {
  db.User.find({ where: { id: req.body.id } }).then(user => {
    if (user.id !== req.user.id) return res.status(403).end();
    user.email = req.body.email;
    user.save().then(() => res.redirect('/app/useredit'));
  });
};
app.post('/useredit', isAuthenticated, userEditSubmit);
