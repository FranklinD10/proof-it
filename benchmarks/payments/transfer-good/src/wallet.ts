export function transfer(from: { balance: number }, to: { balance: number }, amount: number) {
  if (amount <= 0) throw new Error("bad amount");
  if (from.balance < amount) throw new Error("insufficient funds");
  from.balance -= amount;
  to.balance += amount;
}
