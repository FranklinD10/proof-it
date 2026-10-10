// Stand-in for the persistence layer.
export const db = {
  emergencies: {
    async findById(id: string) {
      return { id: Number(id), ownerId: 1, status: "ACTIVE" as const };
    },
    async delete(_id: string) {},
  },
};
