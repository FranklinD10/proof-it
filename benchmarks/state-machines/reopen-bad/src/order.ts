export type OrderStatus = "PENDING" | "PAID" | "SHIPPED" | "CANCELLED";
export function pay(o: { status: OrderStatus }) {
  if (o.status !== "PENDING") throw new Error("not pending");
  o.status = "PAID";
}
export function restore(o: { status: OrderStatus }) {
  o.status = "PENDING";
}
