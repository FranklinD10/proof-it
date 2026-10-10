export function transfer(from: { balance: number }, to: { balance: number }, amount: number) {
  if (amount <= 0) throw new Error("bad amount");
  const fee = amount * 0.015;
  from.balance -= amount + fee;
  to.balance += amount;
}
