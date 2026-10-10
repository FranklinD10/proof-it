export type OrderStatus = "PENDING" | "PAID" | "SHIPPED" | "CANCELLED";
export function retry(o: { status: OrderStatus }) {
  if (!policy.allowsRetry(o.status)) throw new Error("no");
  o.status = "PENDING";
}
