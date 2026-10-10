const Note = require('./note-model');
module.exports = {
  read_note: async (req, res) => {
    const note = await Note.findById(req.params.noteId);
    if (!note) return res.status(404).end();
    if (note.ownerId !== req.user.id) return res.status(403).end();
    res.json(note);
  },
};
