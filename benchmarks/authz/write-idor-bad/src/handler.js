// DVNA-style: user id taken from the form, record saved without an ownership check.
module.exports.userEditSubmit = function (req, res) {
  db.User.find({ where: { id: req.body.id } }).then(user => {
    user.email = req.body.email;
    user.save().then(() => res.redirect('/app/useredit'));
  });
};
app.post('/useredit', isAuthenticated, userEditSubmit);
