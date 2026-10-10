const { gql } = require('apollo-server');
const Note = require('./note');

const typeDefs = gql`
  type Note { id: ID, name: String, body: String, user: String }
  type Query { note(id: ID): Note }
`;

const resolvers = {
  Query: {
    note: async (parent, args, context) => {
      if (typeof context.user === 'undefined') {
        throw new Error('Unauthenticated');
      }
      const note = await Note.findById(args.id);
      if (!note || note.userId !== context.user.id) {
        throw new Error('Not found');
      }
      return note;
    },
  },
};

module.exports = { typeDefs, resolvers };
