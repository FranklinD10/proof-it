export type OrderStatus = "PENDING" | "PAID" | "SHIPPED" | "CANCELLED";
const NEXT: Record<OrderStatus, OrderStatus[]> = { PENDING: ["PAID", "CANCELLED"], PAID: ["SHIPPED"], SHIPPED: [], CANCELLED: [] };
export function advance(o: { status: OrderStatus }, next: OrderStatus) {
  if (!NEXT[o.status].includes(next)) throw new Error("illegal");
  o.status = next;
}
