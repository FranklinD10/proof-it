export const db = {
  emergencies: {
    async findById(id: string) {
      return { id, ownerId: "u1", lat: 6.3, lng: -10.8 };
    },
  },
};
