const jwt = require('jsonwebtoken');
module.exports = {
  validateToken: (req, res, next) => {
    try {
      req.user = jwt.verify(req.headers.authorization.split(' ')[1], process.env.JWT_SECRET, { algorithms: ['HS256'] });
      next();
    } catch (err) {
      res.status(401).send({ error: 'invalid token' });
    }
  },
};
