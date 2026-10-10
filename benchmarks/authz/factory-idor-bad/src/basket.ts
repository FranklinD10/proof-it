import { BasketModel } from "./models";
// Juice Shop style: the route registers the result of a handler factory.
export function retrieveBasket() {
  return async (req: any, res: any) => {
    const id = req.params.id;
    const basket = await BasketModel.findOne({ where: { id } });
    res.json({ data: basket });
  };
}
