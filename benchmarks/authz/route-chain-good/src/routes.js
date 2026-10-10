const controller = require('./notes');
const validateToken = require('./auth').validateToken;
const guard = require('express-jwt-permissions')();

module.exports = (router) => {
  // The permission guard runs after the handler has already responded.
  router.route('/notes/:noteId')
    .get(validateToken, controller.read_note, guard.check(['user:read']));
};
