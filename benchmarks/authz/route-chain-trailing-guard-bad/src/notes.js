const Note = require('./note-model');
module.exports = {
  read_note: async (req, res) => {
    const note = await Note.findById(req.params.noteId);
    res.json(note);
  },
};
